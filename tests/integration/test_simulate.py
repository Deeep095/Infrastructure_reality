"""Integration test for ``reality simulate``: a plan in, a blast radius out.

The database is built once per test by a real scan — the Terraform state
fixture through the real Terraform adapter, and scripted fake clients through
the AWS resources adapter (no boto3, no credentials, no network). A plan JSON
is then written to disk and handed to ``SimulateService`` / the CLI, and the
tests assert what the simulation concluded: replacement selection, address
resolution through the stored mapping, undocumented dependents as HIGH risk,
unresolved addresses reported rather than guessed, and byte-stable JSON. One
test guards the safety contract directly: simulate never spawns a process and
never imports boto3/botocore.
"""

from __future__ import annotations

import builtins
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from reality import cli
from reality.adapters.aws_resources import AwsResourcesAdapter
from reality.domain.enums import ChangeAction, EvidenceSource, ResourceType
from reality.domain.models import Resource, TerraformChange
from reality.services.impact import Assessment, DependentKind, RiskLevel, SimulateService
from reality.services.reconcile import ReconcileService
from reality.services.reports import stable_json
from reality.services.scan import ScanService
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

TESTS = Path(__file__).resolve().parents[1]
AWS_FIXTURES = TESTS / "fixtures" / "aws"
TF_STATE = TESTS / "fixtures" / "terraform" / "state.json"

PROFILE = "sandbox"
REGION = "eu-west-1"

# Identities from the fixtures: declared resources live in the terraform
# namespace, observed ones in the aws namespace, and only the stored address
# mapping may join the two worlds.
TF_WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"
TF_BATCH = "terraform/aws/aws_instance/-/-/aws_instance.batch"
TF_WEB_SG = "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
TF_DB_SG = "terraform/aws/aws_security_group/-/-/module.network.aws_security_group.db_sg"
TF_PRIMARY = "terraform/aws/aws_db_instance/-/-/aws_db_instance.primary"
WEB = "aws/ec2/instance/eu-west-1/123456789012/i-0web"
BATCH = "aws/ec2/instance/eu-west-1/123456789012/i-0batch"
WEB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0aaa111"
DB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0bbb222"
RDS_PRIMARY = "aws/rds/db/eu-west-1/123456789012/primary"

# Only the AWS resources adapter is scanned here; IAM and CloudTrail stay
# unrequested, so their read operations are not part of this module's script.
ALLOWED_OPERATIONS = {
    "get_caller_identity",
    "describe_instances",
    "describe_security_groups",
    "list_functions",
    "describe_db_instances",
    "list_buckets",
}


# --- fakes: one scripted factory, no boto3 required -------------------------------


class FakeClient:
    """A scripted boto3 client that records calls and refuses mutations."""

    def __init__(self, service: str, script: dict[str, list[Any]]) -> None:
        self.service = service
        self._script = script
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str) -> Any:
        if operation.startswith("_"):
            raise AttributeError(operation)

        def _call(**kwargs: Any) -> Any:
            if operation not in ALLOWED_OPERATIONS:
                raise AssertionError(
                    f"{self.service}.{operation} is not an allowed read-only operation"
                )
            self.calls.append((operation, dict(kwargs)))  # a copy: callers may reuse dicts
            queue = self._script[operation]
            if not queue:
                raise AssertionError(f"{self.service}.{operation} called more times than scripted")
            outcome = queue.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return _call


class FakeClientFactory:
    """A client factory that hands out one recorded fake per service."""

    def __init__(self, script: dict[str, dict[str, list[Any]]]) -> None:
        self._script = script
        self.clients: dict[str, FakeClient] = {}

    def __call__(self, service: str) -> FakeClient:
        if service not in self.clients:
            self.clients[service] = FakeClient(service, self._script.get(service, {}))
        return self.clients[service]


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def aws_script() -> dict[str, dict[str, list[Any]]]:
    """The happy-path AWS resources script: identity plus five services."""
    return {
        "sts": {"get_caller_identity": [load(AWS_FIXTURES / "get_caller_identity.json")]},
        "ec2": {
            "describe_instances": list(load(AWS_FIXTURES / "describe_instances.json")["pages"]),
            "describe_security_groups": list(
                load(AWS_FIXTURES / "describe_security_groups.json")["pages"]
            ),
        },
        "lambda": {"list_functions": list(load(AWS_FIXTURES / "list_functions.json")["pages"])},
        "rds": {
            "describe_db_instances": list(
                load(AWS_FIXTURES / "describe_db_instances.json")["pages"]
            )
        },
        "s3": {"list_buckets": [load(AWS_FIXTURES / "list_buckets.json")]},
    }


DATABASE_NAME = "simulate.db"


@pytest.fixture()
def scanned(tmp_path: Path) -> ScanStore:
    """A scanned-and-reconciled database: declared state, observed AWS, findings.

    The AWS resources scan leaves IAM and CloudTrail not requested, which is
    exactly the coverage situation the risk bands must reason about.
    """
    conn = connect(tmp_path / DATABASE_NAME)
    migrate(conn)
    store = ScanStore(conn)
    ScanService(
        store,
        aws_resources=AwsResourcesAdapter(
            profile=PROFILE, region=REGION, client_factory=FakeClientFactory(aws_script())
        ),
    ).run([TF_STATE])
    ReconcileService(store).run()
    yield store
    conn.close()


# --- plan helpers -------------------------------------------------------------------


def write_plan(directory: Path, *changes: dict[str, Any]) -> Path:
    """Write a minimal `terraform show -json` plan document to disk."""
    path = directory / "plan.json"
    path.write_text(json.dumps({"resource_changes": list(changes)}), encoding="utf-8")
    return path


def change(address: str, tf_type: str, *actions: str) -> dict[str, Any]:
    return {"address": address, "type": tf_type, "change": {"actions": list(actions)}}


def map_address_to_observed(store: ScanStore) -> None:
    """Record the legitimate cross-namespace identities: address -> resource."""
    store.terraform_addresses.upsert(
        TerraformChange(
            address="aws_security_group.web_sg",
            tf_resource_type="aws_security_group",
            actions=(ChangeAction.DELETE,),
            canonical_id=WEB_SG,
        )
    )
    store.terraform_addresses.upsert(
        TerraformChange(
            address="module.network.aws_security_group.db_sg",
            tf_resource_type="aws_security_group",
            actions=(ChangeAction.DELETE,),
            canonical_id=DB_SG,
        )
    )


# --- target selection, resolution, and risk ------------------------------------------


def test_multiple_targets_replacement_and_documented_dependents(
    scanned: ScanStore, tmp_path: Path
) -> None:
    plan = write_plan(
        tmp_path,
        change("aws_instance.web", "aws_instance", "delete", "create"),  # delete+create = replace
        change("aws_security_group.web_sg", "aws_security_group", "delete"),
        change("aws_lambda_function.processor", "aws_lambda_function", "update"),  # not selected
    )
    report = SimulateService(scanned).run(plan)

    assert [target.address for target in report.targets] == [
        "aws_instance.web",
        "aws_security_group.web_sg",
    ]
    web, web_sg = report.targets

    # A replacement is selected, classified as REPLACE, and resolved through
    # the address's own terraform-namespace identity. Nothing depends on the
    # declared web instance, and the declared side (state) was consulted.
    assert web.actions == (ChangeAction.REPLACE,)
    assert web.resolved
    assert web.canonical_id == TF_WEB
    assert web.risk is RiskLevel.LOW
    assert web.dependents == ()

    # The security group carries two declared dependents (the instance and the
    # database, both DECLARED_ONLY after reconciliation) -> MEDIUM, not HIGH.
    assert web_sg.resolved
    assert web_sg.canonical_id == TF_WEB_SG
    assert web_sg.risk is RiskLevel.MEDIUM
    kinds = {dependent.canonical_id: dependent.kind for dependent in web_sg.dependents}
    assert kinds == {TF_WEB: DependentKind.DOCUMENTED, TF_PRIMARY: DependentKind.DOCUMENTED}
    assert all(dependent.provenance == ("terraform_declared",) for dependent in web_sg.dependents)

    assert report.risk is RiskLevel.MEDIUM  # the highest target risk


def test_undocumented_dependent_makes_the_target_high(scanned: ScanStore, tmp_path: Path) -> None:
    # Resolve the plan address to the *observed* security group: the stored
    # address mapping is one of the two places a cross-world identity may
    # live (identity mappings are the other).
    map_address_to_observed(scanned)
    plan = write_plan(
        tmp_path, change("module.network.aws_security_group.db_sg", "aws_security_group", "delete")
    )
    report = SimulateService(scanned).run(plan)

    (target,) = report.targets
    assert target.resolved
    assert target.canonical_id == DB_SG
    assert target.risk is RiskLevel.HIGH
    kinds = {dependent.canonical_id: dependent.kind for dependent in target.dependents}
    # The batch instance's attachment is observed but undeclared: the declared
    # aws_instance.batch names sg-0undeclared, which resolves to nothing, so the
    # observed attachment to sg-0bbb222 has no declaration to join. One
    # undocumented dependent is enough for HIGH.
    assert kinds == {BATCH: DependentKind.UNDOCUMENTED}
    batch = next(dependent for dependent in target.dependents if dependent.canonical_id == BATCH)
    assert batch.path == (DB_SG, BATCH)
    assert batch.provenance == ("aws_observed",)
    assert batch.evidence_ids
    assert report.risk is RiskLevel.HIGH  # the one undocumented dependent is enough


def test_unresolved_address_is_reported_not_guessed(scanned: ScanStore, tmp_path: Path) -> None:
    plan = write_plan(tmp_path, change("aws_s3_bucket.archive", "aws_s3_bucket", "delete"))
    report = SimulateService(scanned).run(plan)

    (target,) = report.targets
    assert not target.resolved
    assert target.canonical_id is None
    assert target.risk is None  # unknown, never fabricated
    assert target.dependents == ()
    assert "blast radius not computed" in target.notes[0]
    assert any("could not be resolved" in note for note in report.notes)


def test_plan_without_destructive_targets_has_nothing_to_simulate(
    scanned: ScanStore, tmp_path: Path
) -> None:
    plan = write_plan(
        tmp_path, change("aws_lambda_function.processor", "aws_lambda_function", "update")
    )
    report = SimulateService(scanned).run(plan)

    assert report.targets == ()
    # No destructive targets means nothing was assessed — which is not the
    # same as a low risk.
    assert report.risk is None
    assert report.assessment is Assessment.NOT_APPLICABLE
    assert "no delete or replace targets" in report.notes[0]


def test_unresolved_target_makes_the_assessment_incomplete(
    scanned: ScanStore, tmp_path: Path
) -> None:
    # A delete target that resolves to nothing must not be reported as a clean
    # low-risk plan: the assessment simply did not complete.
    plan = write_plan(tmp_path, change("aws_instance.ghost", "aws_instance", "delete"))
    report = SimulateService(scanned).run(plan)

    assert len(report.targets) == 1
    assert not report.targets[0].resolved
    assert report.risk is None
    assert report.assessment is Assessment.INCOMPLETE


def test_fail_on_unknown_gates_an_incomplete_assessment(
    scanned: ScanStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = write_plan(tmp_path, change("aws_instance.ghost", "aws_instance", "delete"))
    exit_code = cli.main(
        ["--database", str(tmp_path / DATABASE_NAME), "simulate", str(plan), "--fail-on-unknown"]
    )
    assert exit_code == cli.EXIT_POLICY
    # The report is still printed; only the exit code carries the verdict.
    assert "assessment: incomplete" in capsys.readouterr().out


def test_fail_on_unknown_passes_a_complete_assessment(
    scanned: ScanStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    map_address_to_observed(scanned)
    plan = write_plan(tmp_path, change("aws_security_group.web_sg", "aws_security_group", "delete"))
    exit_code = cli.main(
        ["--database", str(tmp_path / DATABASE_NAME), "simulate", str(plan), "--fail-on-unknown"]
    )
    assert exit_code == cli.EXIT_OK
    assert "assessment: complete" in capsys.readouterr().out


def test_unknown_coverage_keeps_the_floor_at_medium(tmp_path: Path) -> None:
    # A database with a mapped resource but no scan coverage at all: no
    # dependent can be ruled out, so LOW is forbidden.
    conn = connect(tmp_path / "fresh.db")
    migrate(conn)
    store = ScanStore(conn)
    with store.scan(source=EvidenceSource.SIMULATION) as session:
        session.upsert_resource(
            Resource(canonical_id=WEB_SG, resource_type=ResourceType.SECURITY_GROUP, provider="aws")
        )
    map_address_to_observed(store)
    plan = write_plan(tmp_path, change("aws_security_group.web_sg", "aws_security_group", "delete"))
    report = SimulateService(store).run(plan)
    conn.close()

    (target,) = report.targets
    assert target.resolved
    assert target.risk is RiskLevel.MEDIUM
    assert target.dependents == ()
    assert any("coverage" in note for note in target.notes)


# --- stability and the safety contract ------------------------------------------------


def test_report_json_is_stable_across_runs(scanned: ScanStore, tmp_path: Path) -> None:
    map_address_to_observed(scanned)
    plan = write_plan(
        tmp_path,
        change("aws_security_group.web_sg", "aws_security_group", "delete"),
        change("aws_s3_bucket.archive", "aws_s3_bucket", "delete"),
    )
    first = SimulateService(scanned).run(plan)
    second = SimulateService(scanned).run(plan)

    assert stable_json(first) == stable_json(second)
    assert "computed_at" not in stable_json(first)  # no timestamps: stable by construction
    parsed = json.loads(stable_json(first))
    assert set(parsed) == {"plan_path", "depth", "risk", "assessment", "targets", "notes"}
    web_sg = next(target for target in parsed["targets"] if target["resolved"])
    # Both of this group's dependents are now CONFIRMED, so the band is MEDIUM:
    # known dependents, nothing undocumented. HIGH needs an undocumented one.
    assert web_sg["risk"] == "medium"
    assert web_sg["dependents"]
    for dependent in web_sg["dependents"]:
        assert set(dependent) == {
            "canonical_id",
            "path",
            "depth",
            "kind",
            "conclusion",
            "provenance",
            "evidence_ids",
        }


def test_no_terraform_or_aws_call_is_made(
    scanned: ScanStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("simulate must never spawn a process or run Terraform")

    for name in ("run", "Popen", "check_call", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, forbidden)
    real_import = builtins.__import__

    def guarded(name: str, *args: object, **kwargs: object) -> object:
        if name in ("boto3", "botocore"):
            raise AssertionError(f"simulate imported {name}; no AWS client may be constructed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    # Snapshot before: boto3 may legitimately already be in sys.modules because
    # an earlier test in this session imported it (the AWS adapter tests do,
    # whenever boto3 is installed). What matters is that *simulate* adds
    # nothing, so the assertion is on the delta, not on the global state.
    before = set(sys.modules)
    plan = write_plan(tmp_path, change("aws_instance.web", "aws_instance", "delete"))
    report = SimulateService(scanned).run(plan)

    assert report.targets[0].resolved  # the run completed
    new_aws_modules = {
        name for name in set(sys.modules) - before if name.startswith(("boto3", "botocore"))
    }
    assert new_aws_modules == set(), f"simulate newly imported {new_aws_modules}"
    # The guarded __import__ above is the real guarantee: if simulate had tried
    # to construct a client it would have raised before reaching here.


def test_simulate_writes_nothing_to_the_database(scanned: ScanStore, tmp_path: Path) -> None:
    tables = (
        "scan_runs",
        "resources",
        "relationships",
        "evidence",
        "coverage",
        "findings",
        "terraform_addresses",
        "identity_mappings",
    )
    before = {
        table: scanned.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in tables
    }
    plan = write_plan(
        tmp_path,
        change("aws_instance.web", "aws_instance", "delete"),
        change("aws_s3_bucket.archive", "aws_s3_bucket", "delete"),
    )
    SimulateService(scanned).run(plan)

    after = {
        table: scanned.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in tables
    }
    assert after == before


# --- the CLI command --------------------------------------------------------------------


def test_cli_simulate_reports_risk_in_plain_text(
    scanned: ScanStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = write_plan(tmp_path, change("aws_instance.web", "aws_instance", "delete"))
    exit_code = cli.main(["--database", str(tmp_path / DATABASE_NAME), "simulate", str(plan)])
    assert exit_code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith(f"reality: simulate {plan}")
    assert "read-only; the plan is never applied" in out
    assert "overall risk: low" in out
    assert f"aws_instance.web [delete] -> {TF_WEB}" in out


def test_cli_simulate_json_is_parseable(
    scanned: ScanStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    map_address_to_observed(scanned)
    plan = write_plan(tmp_path, change("aws_security_group.web_sg", "aws_security_group", "delete"))
    exit_code = cli.main(
        ["--database", str(tmp_path / DATABASE_NAME), "simulate", str(plan), "--json"]
    )
    assert exit_code == cli.EXIT_OK
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["risk"] == "medium"
    (target,) = parsed["targets"]
    assert target["canonical_id"] == WEB_SG
    assert {dependent["canonical_id"] for dependent in target["dependents"]} == {WEB, RDS_PRIMARY}


def test_cli_simulate_rejects_unreadable_and_invalid_plans(
    scanned: ScanStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = str(tmp_path / DATABASE_NAME)
    exit_code = cli.main(["--database", database, "simulate", str(tmp_path / "missing.json")])
    assert exit_code == cli.EXIT_INPUT
    assert "could not read" in capsys.readouterr().err

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    exit_code = cli.main(["--database", database, "simulate", str(bad)])
    assert exit_code == cli.EXIT_INPUT
    assert "invalid JSON" in capsys.readouterr().err


def test_cli_simulate_needs_an_existing_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = write_plan(tmp_path, change("aws_instance.web", "aws_instance", "delete"))
    exit_code = cli.main(["--database", str(tmp_path / "nope.db"), "simulate", str(plan)])
    assert exit_code == cli.EXIT_INPUT
    assert "database not found" in capsys.readouterr().err


def test_cli_depth_must_be_positive() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["simulate", "plan.json", "--depth", "0"])
    assert exc.value.code == cli.EXIT_USAGE
