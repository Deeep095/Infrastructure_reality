"""Unit tests for the CLI shell: help, command registration, the AWS gate, and scan wiring.

Scan tests run fully offline: local-only scans use the Terraform fixtures,
and tests that need the AWS opt-in triple stub the scan service so no boto3
client is ever constructed and no network is touched.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reality import cli
from reality.domain.enums import CoverageStatus
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
            def from_config(cls, config, store, *, cloudtrail_window=None, client_factory=None):
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
            def from_config(cls, config, store, *, cloudtrail_window=None, client_factory=None):
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


def test_reconcile_reports_not_implemented(capsys: pytest.CaptureFixture[str]) -> None:
    # The only command still awaiting its phase; why/impact/simulate are wired.
    assert cli.main(["reconcile"]) == cli.EXIT_NOT_IMPLEMENTED
    assert "not implemented" in capsys.readouterr().err


def test_database_flag_reaches_config() -> None:
    args = cli.build_parser().parse_args(["--database", "elsewhere.db", "reconcile"])
    assert args.database.name == "elsewhere.db"
