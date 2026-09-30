"""Integration test for the scan orchestrator: fixtures in, one transaction out.

Feeds a real local Terraform state document through the Terraform adapter and
scripted fake clients through the AWS, IAM, and CloudTrail adapters, then
asserts what the scan persisted in a temporary database: resources,
relationships, evidence, and coverage — including NOT_REQUESTED records for
sources that were never consulted. No boto3 import, no credentials, no
network, and no writes outside the temporary database; the fake client
refuses every operation outside the three adapters' combined read-only
whitelist.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from reality.config import RealityConfig
from reality.domain.enums import (
    CoverageStatus,
    EvidenceSource,
    RelationshipOrigin,
    RelationshipType,
)
from reality.services.scan import ScanInputError, ScanService
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

TESTS = Path(__file__).resolve().parents[1]
AWS_FIXTURES = TESTS / "fixtures" / "aws"
IAM_FIXTURES = TESTS / "fixtures" / "iam"
CLOUDTRAIL_FIXTURES = TESTS / "fixtures" / "cloudtrail"
TF_STATE = TESTS / "fixtures" / "terraform" / "state.json"
TF_PLAN = TESTS / "fixtures" / "terraform" / "plan_replace.json"

PROFILE = "sandbox"
REGION = "eu-west-1"
ACCOUNT = "123456789012"
START = datetime(2026, 3, 1, 0, 0, tzinfo=UTC)
END = datetime(2026, 3, 2, 0, 0, tzinfo=UTC)

# Canonical keys asserted below: one declared (Terraform namespace) and one
# observed (AWS namespace) identity per interesting resource. They are
# deliberately distinct — joining the two worlds is reconciliation's job, not
# the scan's.
TF_WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"
TF_BATCH = "terraform/aws/aws_instance/-/-/aws_instance.batch"
TF_WEB_SG = "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
TF_DB_SG = "terraform/aws/aws_security_group/-/-/module.network.aws_security_group.db_sg"
TF_PROCESSOR = "terraform/aws/aws_lambda_function/-/-/aws_lambda_function.processor"
TF_PROCESSOR_ROLE = "terraform/aws/aws_iam_role/-/-/aws_iam_role.processor_role"
TF_PRIMARY = "terraform/aws/aws_db_instance/-/-/aws_db_instance.primary"
WEB = "aws/ec2/instance/eu-west-1/123456789012/i-0web"
BATCH = "aws/ec2/instance/eu-west-1/123456789012/i-0batch"
WEB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0aaa111"
DB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0bbb222"
RDS_PRIMARY = "aws/rds/db/eu-west-1/123456789012/primary"
PROCESSOR = "aws/lambda/function/eu-west-1/123456789012/processor"
PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
# A bucket ARN carries no account, so references to it stay account-less even
# though the discovered bucket row carries the scan account.
DATA_LAKE_OBSERVED = "aws/s3/bucket/-/123456789012/data-lake"
DATA_LAKE_REFERENCED = "aws/s3/bucket/-/-/data-lake"

#: Every identity mapping the full happy-path scan must produce, as
#: terraform_id -> aws_id. The deliberate absences matter as much: the web
#: instance (state ARN names i-0abc123def456, the observed one is i-0web),
#: the data bucket (acme-customer-data is not among the observed buckets),
#: the CDN (no ARN in state, nothing observed), and the batch instance
#: (i-0batch789 is not i-0batch) all stay unmapped.
EXPECTED_MAPPINGS = {
    TF_WEB: WEB,
    TF_BATCH: BATCH,
    TF_WEB_SG: WEB_SG,
    TF_DB_SG: DB_SG,
    TF_PROCESSOR: PROCESSOR,
    TF_PROCESSOR_ROLE: PROCESSOR_ROLE,
    TF_PRIMARY: RDS_PRIMARY,
}

# The union of every operation the three AWS-side adapters may issue.
ALLOWED_OPERATIONS = {
    "get_caller_identity",
    "describe_instances",
    "describe_security_groups",
    "list_functions",
    "describe_db_instances",
    "list_buckets",
    "list_roles",
    "list_role_policies",
    "get_role_policy",
    "list_attached_role_policies",
    "get_policy",
    "get_policy_version",
    "lookup_events",
}


# --- fakes: one scripted factory for all services, no boto3 required --------


class FakeClientError(Exception):
    """Mimics ``botocore.exceptions.ClientError``'s ``.response`` shape."""

    def __init__(self, code: str, message: str = "simulated failure") -> None:
        super().__init__(f"{code}: {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


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


def full_script() -> dict[str, dict[str, list[Any]]]:
    """The combined happy-path script: AWS resources, IAM roles, CloudTrail."""
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
        "iam": {
            "list_roles": list(load(IAM_FIXTURES / "list_roles.json")["pages"]),
            "list_role_policies": [
                *load(IAM_FIXTURES / "list_role_policies_processor.json")["pages"],
                load(IAM_FIXTURES / "list_role_policies_cleanup.json"),
                load(IAM_FIXTURES / "list_role_policies_auditor.json"),
            ],
            "get_role_policy": [
                load(IAM_FIXTURES / "get_role_policy_processor_inline.json"),
                load(IAM_FIXTURES / "get_role_policy_processor_readonly.json"),
                load(IAM_FIXTURES / "get_role_policy_cleanup_inline.json"),
                load(IAM_FIXTURES / "get_role_policy_auditor_inline.json"),
            ],
            "list_attached_role_policies": [
                load(IAM_FIXTURES / "list_attached_role_policies_processor.json"),
                load(IAM_FIXTURES / "list_attached_role_policies_cleanup.json"),
                load(IAM_FIXTURES / "list_attached_role_policies_auditor.json"),
            ],
            "get_policy": [
                load(IAM_FIXTURES / "get_policy_data_reader.json"),
                load(IAM_FIXTURES / "get_policy_auditor_access.json"),
            ],
            "get_policy_version": [
                load(IAM_FIXTURES / "get_policy_version_data_reader_v2.json"),
                load(IAM_FIXTURES / "get_policy_version_auditor_access_v1.json"),
            ],
        },
        "cloudtrail": {
            "lookup_events": list(load(CLOUDTRAIL_FIXTURES / "lookup_events.json")["pages"])
        },
    }


def make_service(
    store: ScanStore, script: dict[str, dict[str, list[Any]]] | None = None
) -> ScanService:
    config = RealityConfig(aws_opt_in=True, aws_profile=PROFILE, aws_region=REGION)
    return ScanService.from_config(
        config,
        store,
        cloudtrail_window=(START, END),
        client_factory=FakeClientFactory(script if script is not None else full_script()),
    )


@pytest.fixture()
def store(tmp_path: Path) -> ScanStore:
    conn = connect(tmp_path / "scan.db")
    migrate(conn)
    yield ScanStore(conn)
    conn.close()


# --- the full scan -------------------------------------------------------------


def test_full_scan_persists_all_sources_in_one_run(store: ScanStore) -> None:
    report = make_service(store).run([TF_STATE])

    # The report names every source and its status — all four requested and
    # available in this happy path.
    statuses = {source.source: source.status for source in report.sources}
    assert statuses == {
        "terraform": CoverageStatus.AVAILABLE,
        "aws_resources": CoverageStatus.AVAILABLE,
        "iam": CoverageStatus.AVAILABLE,
        "cloudtrail": CoverageStatus.AVAILABLE,
    }
    assert report.scan_run_id == 1
    assert report.region == REGION
    assert report.account == ACCOUNT

    # One scan run, finished, anchored on the declared world, with context.
    assert store.scan_runs.count() == 1
    row = store.conn.execute("SELECT * FROM scan_runs").fetchone()
    assert row["source"] == "terraform_state"
    assert row["region"] == REGION
    assert row["account"] == ACCOUNT
    assert row["finished_at"] is not None

    # Resources from both worlds, each under its own canonical ID.
    for canonical_id in (
        TF_WEB,
        TF_WEB_SG,
        TF_PROCESSOR,
        WEB,
        WEB_SG,
        PROCESSOR,
        PROCESSOR_ROLE,
        DATA_LAKE_OBSERVED,
    ):
        assert store.resources.get(canonical_id) is not None, canonical_id

    # Observed links carry their evidence, and that evidence is persisted.
    outgoing = store.relationships.outgoing(WEB)
    attached = next(
        r
        for r in outgoing
        if r.type == RelationshipType.ATTACHED_TO and r.target_canonical_id == WEB_SG
    )
    assert attached.origin == RelationshipOrigin.AWS_OBSERVED
    assert attached.evidence_ids
    for evidence_id in attached.evidence_ids:
        assert store.evidence.get(evidence_id) is not None

    # Declared links live in their own namespace with their own origin.
    tf_outgoing = store.relationships.outgoing(TF_WEB)
    assert any(
        r.origin == RelationshipOrigin.TERRAFORM_DECLARED and r.type == RelationshipType.REFERENCES
        for r in tf_outgoing
    )

    # IAM permission evidence and CloudTrail observed usage both connect the
    # role to the bucket it touches, as separate relationships.
    role_links = store.relationships.outgoing(PROCESSOR_ROLE)
    permission = next(
        r
        for r in role_links
        if r.type == RelationshipType.PERMISSION_ON
        and r.target_canonical_id == DATA_LAKE_REFERENCED
    )
    assert permission.origin == RelationshipOrigin.IAM_POLICY
    assert permission.evidence_ids
    observed = next(
        r
        for r in role_links
        if r.type == RelationshipType.DEPENDS_ON and r.origin == RelationshipOrigin.CLOUDTRAIL
    )
    assert observed.target_canonical_id == DATA_LAKE_REFERENCED
    assert observed.evidence_ids

    # Coverage: every requested source recorded, none NOT_REQUESTED.
    records = store.coverage.all_records()
    assert {
        EvidenceSource.TERRAFORM_STATE,
        EvidenceSource.AWS_RESOURCES,
        EvidenceSource.IAM,
        EvidenceSource.CLOUDTRAIL,
    } <= {record.source for record in records}
    assert all(record.status != CoverageStatus.NOT_REQUESTED for record in records)
    assert report.coverage == len(records)

    # Identity mappings: exact ARN joins from the state to the observed world,
    # both identities preserved, each backed by its own evidence row.
    assert report.identity_mappings == len(EXPECTED_MAPPINGS)
    mappings = store.identity_mappings.for_scan_run(1)
    assert {m.terraform_canonical_id: m.aws_canonical_id for m in mappings} == EXPECTED_MAPPINGS
    for mapping in mappings:
        # Most joins are ARN-based. aws_instance.batch carries no ARN in the
        # state, so it joins on its native ID instead - the same exact-identifier
        # rule, a different field.
        assert mapping.basis.value in ("arn", "native_id")
        evidence = store.evidence.get(mapping.evidence_id)
        assert evidence is not None, mapping.evidence_id
        assert evidence.type.value == "identity_match"
        assert evidence.source_canonical_id == mapping.terraform_canonical_id
        assert evidence.target_canonical_id == mapping.aws_canonical_id
        row = store.conn.execute(
            "SELECT scan_run_id FROM evidence WHERE id = ?", (mapping.evidence_id,)
        ).fetchone()
        assert row["scan_run_id"] == 1  # anchored to the scan that saw both sides
    # The report's evidence count includes the mapping evidence.
    assert report.evidence == store.evidence.count()

    # Everything this scan wrote is anchored to its single scan run.
    total = store.resources.count()
    anchored = store.conn.execute(
        "SELECT COUNT(*) FROM resources WHERE scan_run_id = 1"
    ).fetchone()[0]
    assert anchored == total


def test_rescanning_is_idempotent(store: ScanStore) -> None:
    make_service(store).run([TF_STATE])
    counts = {
        table: store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("resources", "relationships", "evidence", "identity_mappings")
    }
    make_service(store).run([TF_STATE])  # a fresh script, the same facts
    assert store.scan_runs.count() == 2
    for table, count in counts.items():
        assert store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == count
    # The second run's mappings replace the first run's anchors: the same
    # joins, now backed by the newer scan.
    assert {m.terraform_canonical_id for m in store.identity_mappings.for_scan_run(2)} == set(
        EXPECTED_MAPPINGS
    )


# --- reduced coverage and refusals ---------------------------------------------


def test_local_only_scan_records_unrequested_sources(store: ScanStore) -> None:
    service = ScanService.from_config(RealityConfig(), store)  # no AWS opt-in
    report = service.run([TF_STATE])

    statuses = {source.source: source.status for source in report.sources}
    assert statuses["terraform"] == CoverageStatus.AVAILABLE
    assert [statuses[name] for name in ("aws_resources", "iam", "cloudtrail")] == [
        CoverageStatus.NOT_REQUESTED
    ] * 3

    not_requested = [
        record
        for record in store.coverage.all_records()
        if record.status == CoverageStatus.NOT_REQUESTED
    ]
    assert {record.source for record in not_requested} == {
        EvidenceSource.AWS_RESOURCES,
        EvidenceSource.IAM,
        EvidenceSource.CLOUDTRAIL,
    }

    # The scan context stays local: no region or account is claimed.
    row = store.conn.execute("SELECT * FROM scan_runs").fetchone()
    assert row["region"] is None
    assert row["account"] is None
    assert store.resources.get(TF_WEB) is not None  # declared facts still persist


def test_aws_failure_is_reduced_coverage_not_a_failed_scan(store: ScanStore) -> None:
    script = full_script()
    script["sts"] = {"get_caller_identity": [FakeClientError("AccessDenied")]}
    report = make_service(store, script).run([TF_STATE])

    statuses = {source.source: source.status for source in report.sources}
    assert statuses["aws_resources"] == CoverageStatus.UNAVAILABLE
    assert statuses["iam"] == CoverageStatus.AVAILABLE
    assert statuses["terraform"] == CoverageStatus.AVAILABLE

    # The scan still succeeded and persisted everything it could collect.
    assert store.scan_runs.count() == 1
    assert store.resources.get(TF_WEB) is not None
    assert store.resources.get(PROCESSOR_ROLE) is not None  # IAM was unaffected
    unavailable = [
        record
        for record in store.coverage.all_records()
        if record.status == CoverageStatus.UNAVAILABLE
        and record.source == EvidenceSource.AWS_RESOURCES
    ]
    assert unavailable
    assert "GetCallerIdentity" in unavailable[0].reason


def test_invalid_local_input_writes_nothing(tmp_path: Path, store: ScanStore) -> None:
    service = ScanService.from_config(RealityConfig(), store)
    with pytest.raises(ScanInputError, match="could not read"):
        service.run([tmp_path / "missing.json"])
    assert store.scan_runs.count() == 0
    assert store.resources.count() == 0
    assert store.evidence.count() == 0


def test_plan_scan_persists_declared_changes(store: ScanStore) -> None:
    service = ScanService.from_config(RealityConfig(), store)
    report = service.run([TF_PLAN])

    assert report.scan_run_id == 1
    row = store.conn.execute("SELECT * FROM scan_runs").fetchone()
    assert row["source"] == "terraform_plan"  # a plan-only scan anchors on the plan
    change = store.terraform_addresses.get("aws_instance.web")
    assert change is not None
    assert [action.value for action in change.actions] == ["replace"]
    assert change.canonical_id == TF_WEB
