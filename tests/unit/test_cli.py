"""Unit tests for the CLI shell: help, command registration, the AWS gate, and scan wiring.

Scan tests run fully offline: local-only scans use the Terraform fixtures,
and tests that need the AWS opt-in triple stub the scan service so no boto3
client is ever constructed and no network is touched.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reality import cli
from reality.domain.enums import CoverageStatus
from reality.services.impact import RiskLevel
from reality.services.scan import ScanReport, SourceReport

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"


def test_help_works_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "usage: reality" in out
    # --help must work even though no command is implemented yet.
    for command in ("scan", "reconcile", "why", "impact", "simulate"):
        assert command in out


def test_no_command_prints_usage_and_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == cli.EXIT_USAGE
    assert "usage: reality" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["scan"],
        ["reconcile"],
        ["why", "i-abc123"],
        ["impact", "i-abc123"],
        ["simulate", "plan.json"],
    ],
)
def test_all_commands_are_registered(argv: list[str]) -> None:
    args = cli.build_parser().parse_args(argv)
    assert args.command == argv[0]


def test_unknown_command_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["explode"])
    assert exc.value.code == cli.EXIT_USAGE


class TestScanLocalInput:
    def test_local_scan_runs_without_aws(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        exit_code = cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        assert exit_code == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "terraform: available" in out
        assert "aws_resources: not_requested" in out
        assert "iam: not_requested" in out
        assert "cloudtrail: not_requested" in out
        assert database.exists()

    def test_nothing_to_scan_is_rejected(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(["--database", str(tmp_path / "scan.db"), "scan"])
        assert exit_code == cli.EXIT_CONFIG
        assert "nothing to scan" in capsys.readouterr().err

    def test_missing_local_input_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(
            ["--database", str(tmp_path / "scan.db"), "scan", str(tmp_path / "nope.json")]
        )
        assert exit_code == cli.EXIT_INPUT
        assert "could not read" in capsys.readouterr().err

    def test_malformed_local_input_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(
            ["--database", str(tmp_path / "scan.db"), "scan", str(FIXTURES / "malformed.json")]
        )
        assert exit_code == cli.EXIT_INPUT
        assert "rejected" in capsys.readouterr().err

    def test_invalid_input_writes_no_database_rows(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        # A valid path first so the database and schema exist, then a bad one.
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        exit_code = cli.main(
            ["--database", str(database), "scan", str(FIXTURES / "malformed.json")]
        )
        assert exit_code == cli.EXIT_INPUT
        conn = sqlite3.connect(database)
        try:
            runs = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
        finally:
            conn.close()
        assert runs == 1  # only the first, valid scan; the refused one wrote nothing


class TestScanAwsOptIn:
    def test_partial_triple_is_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["--aws", "scan"]) == cli.EXIT_CONFIG
        assert cli.main(["--aws", "--profile", "sandbox", "scan"]) == cli.EXIT_CONFIG
        assert cli.main(["--aws", "--region", "eu-west-1", "scan"]) == cli.EXIT_CONFIG
        assert "--profile" in capsys.readouterr().err

    def test_full_triple_reaches_the_scan_service(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        calls: dict[str, object] = {}

        class FakeService:
            @classmethod
            def from_config(
                cls, config, store, *, cloudtrail_window=None, client_factory=None, progress=None
            ):
                calls["config"] = config
                calls["window"] = cloudtrail_window
                return cls()

            def run(self, terraform_paths=()):
                calls["paths"] = tuple(terraform_paths)
                return ScanReport(
                    scan_run_id=7,
                    sources=(
                        SourceReport(
                            source="terraform",
                            status=CoverageStatus.NOT_REQUESTED,
                            detail="stubbed",
                        ),
                    ),
                )

        monkeypatch.setattr(cli, "ScanService", FakeService)
        state = FIXTURES / "state.json"
        exit_code = cli.main(
            [
                "--database",
                str(tmp_path / "scan.db"),
                "--aws",
                "--profile",
                "sandbox",
                "--region",
                "eu-west-1",
                "scan",
                str(state),
            ]
        )
        assert exit_code == cli.EXIT_OK
        assert calls["config"].aws_ready
        assert calls["window"] is None
        assert calls["paths"] == (state,)
        assert "scan 7 complete" in capsys.readouterr().out


class TestScanCloudTrailWindow:
    def test_window_without_aws_is_rejected(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(
            [
                "--database",
                str(tmp_path / "scan.db"),
                "scan",
                "--cloudtrail-start",
                "2026-03-01T00:00:00+00:00",
                "--cloudtrail-end",
                "2026-03-02T00:00:00+00:00",
                str(FIXTURES / "state.json"),
            ]
        )
        assert exit_code == cli.EXIT_CONFIG
        assert "--aws" in capsys.readouterr().err

    def test_window_needs_both_bounds(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The both-bounds check fires before any adapter is constructed, so
        # this runs offline even with the full triple on the command line.
        exit_code = cli.main(
            [
                "--database",
                str(tmp_path / "scan.db"),
                "--aws",
                "--profile",
                "sandbox",
                "--region",
                "eu-west-1",
                "scan",
                "--cloudtrail-start",
                "2026-03-01T00:00:00+00:00",
            ]
        )
        assert exit_code == cli.EXIT_CONFIG
        assert "together" in capsys.readouterr().err

    def test_window_must_carry_an_offset(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The offset check fires before any adapter is constructed, so this
        # runs offline even with the full triple on the command line.
        exit_code = cli.main(
            [
                "--database",
                str(tmp_path / "scan.db"),
                "--aws",
                "--profile",
                "sandbox",
                "--region",
                "eu-west-1",
                "scan",
                "--cloudtrail-start",
                "2026-03-01T00:00:00",
                "--cloudtrail-end",
                "2026-03-02T00:00:00",
                str(FIXTURES / "state.json"),
            ]
        )
        assert exit_code == cli.EXIT_CONFIG
        assert "offset" in capsys.readouterr().err

    def test_window_reaches_the_scan_service(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        calls: dict[str, object] = {}

        class FakeService:
            @classmethod
            def from_config(
                cls, config, store, *, cloudtrail_window=None, client_factory=None, progress=None
            ):
                calls["window"] = cloudtrail_window
                return cls()

            def run(self, terraform_paths=()):
                return ScanReport(scan_run_id=1)

        monkeypatch.setattr(cli, "ScanService", FakeService)
        exit_code = cli.main(
            [
                "--database",
                str(tmp_path / "scan.db"),
                "--aws",
                "--profile",
                "sandbox",
                "--region",
                "eu-west-1",
                "scan",
                "--cloudtrail-start",
                "2026-03-01T00:00:00+00:00",
                "--cloudtrail-end",
                "2026-03-02T00:00:00+00:00",
            ]
        )
        assert exit_code == cli.EXIT_OK
        assert calls["window"] == (
            datetime(2026, 3, 1, tzinfo=UTC),
            datetime(2026, 3, 2, tzinfo=UTC),
        )


def test_partial_aws_flags_rejected_on_any_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # --profile without --aws implies implicit AWS usage; reject it.
    assert cli.main(["--profile", "sandbox", "why", "i-abc123"]) == cli.EXIT_CONFIG
    assert cli.main(["--region", "eu-west-1", "why", "i-abc123"]) == cli.EXIT_CONFIG


def test_database_flag_reaches_config() -> None:
    args = cli.build_parser().parse_args(["--database", "elsewhere.db", "reconcile"])
    assert args.database.name == "elsewhere.db"


class TestReconcileCommand:
    """`reconcile` is wired: it reconciles a scan and writes findings."""

    def test_missing_database_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(["--database", str(tmp_path / "absent.db"), "reconcile"])
        assert exit_code == cli.EXIT_INPUT
        assert "run reality scan first" in capsys.readouterr().err

    def test_reconcile_after_a_scan_succeeds(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        assert cli.main(["--database", str(database), "reconcile"]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "reality: reconcile pass" in out
        # A local-only scan consulted neither AWS side, so every conclusion is
        # UNKNOWN and the report must say which coverage is missing.
        assert "unknown" in out
        assert "missing coverage: aws_resources" in out

    def test_reconcile_with_no_discovery_scan_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # An existing but empty database: reconciling nothing is an error, not
        # an empty result.
        database = tmp_path / "empty.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        conn = sqlite3.connect(database)
        try:
            conn.execute("DELETE FROM scan_runs")
            conn.commit()
        finally:
            conn.close()
        assert cli.main(["--database", str(database), "reconcile"]) == cli.EXIT_INPUT
        assert "no discovery scan" in capsys.readouterr().err

    def test_unknown_scan_run_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        exit_code = cli.main(["--database", str(database), "reconcile", "--scan-run", "999"])
        assert exit_code == cli.EXIT_INPUT
        assert "does not exist" in capsys.readouterr().err

    def test_reconcile_of_its_own_pass_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        assert cli.main(["--database", str(database), "reconcile"]) == cli.EXIT_OK
        capsys.readouterr()
        # Scan run 2 is the reconciliation pass itself; analysing it would read
        # its own conclusions back as evidence.
        assert cli.main(["--database", str(database), "reconcile", "--scan-run", "2"]) == (
            cli.EXIT_INPUT
        )
        assert "reconciliation pass" in capsys.readouterr().err

    def test_findings_are_byte_stable_across_passes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        capsys.readouterr()
        assert cli.main(["--database", str(database), "reconcile", "--json"]) == cli.EXIT_OK
        first = capsys.readouterr().out
        assert cli.main(["--database", str(database), "reconcile", "--json"]) == cli.EXIT_OK
        second = capsys.readouterr().out
        # The whole document is not byte-identical and should not be: each pass
        # is a new scan run, so scan_run_id advances. The conclusions are what
        # a CI diff cares about, and those must not move.
        assert json.loads(first)["findings"] == json.loads(second)["findings"]
        assert json.loads(first)["counts"] == json.loads(second)["counts"]
        assert json.loads(second)["scan_run_id"] > json.loads(first)["scan_run_id"]

    @pytest.mark.parametrize("output", ["text", "table", "json", "yaml", "csv"])
    def test_every_output_format_renders(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], output: str
    ) -> None:
        if output == "table":
            # rich is an optional extra; test_optional_deps.py covers both the
            # present and absent cases explicitly, so skip here rather than
            # assume a dev environment always has it.
            pytest.importorskip("rich")
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        capsys.readouterr()
        assert (
            cli.main(["--database", str(database), "reconcile", "--output", output]) == cli.EXIT_OK
        )
        assert capsys.readouterr().out.strip()


class TestResourceIdResolution:
    """A user may name a resource the way they read it off a plan."""

    @pytest.fixture()
    def database(self, tmp_path: Path) -> Path:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        return database

    def test_terraform_address_resolves(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            cli.main(["--database", str(database), "why", "aws_security_group.web_sg", "--json"])
            == cli.EXIT_OK
        )
        assert json.loads(capsys.readouterr().out)["resource"]["canonical_id"] == (
            "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
        )

    def test_module_address_resolves(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            cli.main(
                [
                    "--database",
                    str(database),
                    "why",
                    "module.network.aws_security_group.db_sg",
                    "--json",
                ]
            )
            == cli.EXIT_OK
        )
        assert json.loads(capsys.readouterr().out)["resource"]["canonical_id"] == (
            "terraform/aws/aws_security_group/-/-/module.network.aws_security_group.db_sg"
        )

    def test_native_id_resolves(self, database: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # A local-only scan stored the declared side only, so this native ID
        # names exactly one resource. The ambiguous case — one native ID on
        # both sides of the two worlds — is covered by the demo world.
        assert cli.main(["--database", str(database), "why", "sg-0aaa111", "--json"]) == cli.EXIT_OK
        assert json.loads(capsys.readouterr().out)["resource"]["canonical_id"] == (
            "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
        )

    def test_unique_native_id_resolves(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            cli.main(["--database", str(database), "why", "acme-customer-data", "--json"])
            == cli.EXIT_OK
        )
        assert json.loads(capsys.readouterr().out)["resource"]["canonical_id"] == (
            "terraform/aws/aws_s3_bucket/-/-/aws_s3_bucket.data"
        )

    def test_short_display_form_still_resolves(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            cli.main(
                [
                    "--database",
                    str(database),
                    "why",
                    "terraform:aws/aws_security_group.web_sg",
                    "--json",
                ]
            )
            == cli.EXIT_OK
        )
        assert json.loads(capsys.readouterr().out)["resource"]["canonical_id"] == (
            "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
        )

    def test_full_canonical_id_passes_through(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        canonical = "terraform/aws/aws_db_instance/-/-/aws_db_instance.primary"
        assert cli.main(["--database", str(database), "why", canonical, "--json"]) == cli.EXIT_OK
        assert json.loads(capsys.readouterr().out)["resource"]["canonical_id"] == canonical

    def test_unknown_id_is_refused(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert cli.main(["--database", str(database), "why", "no-such-thing"]) == cli.EXIT_INPUT
        assert "not found" in capsys.readouterr().err

    def test_impact_accepts_a_terraform_address(
        self, database: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            cli.main(["--database", str(database), "impact", "aws_security_group.web_sg", "--json"])
            == cli.EXIT_OK
        )
        assert json.loads(capsys.readouterr().out)["subject_canonical_id"] == (
            "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
        )


class TestFailOn:
    """`--fail-on` reports the caller's own policy verdict in the exit code."""

    def test_never_is_the_default(self) -> None:
        assert cli.build_parser().parse_args(["impact", "x"]).fail_on == cli.FailOn.NEVER
        assert cli.build_parser().parse_args(["simulate", "p.json"]).fail_on == cli.FailOn.NEVER

    @pytest.mark.parametrize(
        ("risk", "threshold", "expected"),
        [
            (RiskLevel.HIGH, cli.FailOn.HIGH, cli.EXIT_POLICY),
            (RiskLevel.HIGH, cli.FailOn.MEDIUM, cli.EXIT_POLICY),
            (RiskLevel.MEDIUM, cli.FailOn.HIGH, cli.EXIT_OK),
            (RiskLevel.MEDIUM, cli.FailOn.MEDIUM, cli.EXIT_POLICY),
            (RiskLevel.LOW, cli.FailOn.MEDIUM, cli.EXIT_OK),
            (RiskLevel.LOW, cli.FailOn.HIGH, cli.EXIT_OK),
            (RiskLevel.HIGH, cli.FailOn.NEVER, cli.EXIT_OK),
            (RiskLevel.LOW, cli.FailOn.NEVER, cli.EXIT_OK),
        ],
    )
    def test_threshold_comparison(self, risk: RiskLevel, threshold: str, expected: int) -> None:
        assert cli._fail_on(risk, threshold) == expected

    def test_high_risk_trips_the_gate_and_still_prints(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        # MEDIUM is the documented result for this graph with no AWS coverage,
        # so `medium` is the threshold that trips here.
        subject = "aws_security_group.web_sg"
        assert (
            cli.main(["--database", str(database), "impact", subject, "--fail-on", "medium"])
            == cli.EXIT_POLICY
        )
        assert "risk: medium" in capsys.readouterr().out
        # Without the flag the same command still succeeds.
        assert cli.main(["--database", str(database), "impact", subject]) == cli.EXIT_OK
        capsys.readouterr()
        assert (
            cli.main(["--database", str(database), "impact", subject, "--fail-on", "high"])
            == cli.EXIT_OK
        )


class TestGlobalFlagOrdering:
    """Global flags must work before OR after the subcommand.

    ``--database``, ``--aws``, ``--profile`` and ``--region`` are global, but
    argparse rejects them after a subcommand unless the subparser also declares
    them. Users routinely type them in the wrong order and get an unexplained
    "unrecognized arguments", so both positions are accepted.
    """

    def test_flags_before_the_subcommand(self, tmp_path: Path) -> None:
        database = tmp_path / "before.db"
        assert (
            cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
            == cli.EXIT_OK
        )
        assert database.exists()

    def test_flags_after_the_subcommand(self, tmp_path: Path) -> None:
        database = tmp_path / "after.db"
        assert (
            cli.main(["scan", "--database", str(database), str(FIXTURES / "state.json")])
            == cli.EXIT_OK
        )
        assert database.exists()

    def test_flags_split_across_both_positions(self, tmp_path: Path) -> None:
        database = tmp_path / "split.db"
        assert (
            cli.main(
                [
                    "--database",
                    str(database),
                    "scan",
                    "--database",
                    str(database),
                    str(FIXTURES / "state.json"),
                ]
            )
            == cli.EXIT_OK
        )
        assert database.exists()

    def test_default_database_when_flag_omitted(self, tmp_path: Path) -> None:
        # No --database anywhere: the built-in default is used, and the command
        # still succeeds rather than failing on a missing flag.
        exit_code = cli.main(["scan", str(FIXTURES / "state.json")])
        assert exit_code == cli.EXIT_OK
