"""End-to-end reconciliation proofs across the two correctness gaps.

One module, three proofs, all against the same fixture world and the same
scripted fake clients as the other integration tests (no boto3, no network,
no credentials, no writes outside the temporary database):

1. **Identity joins.** Terraform and AWS evidence about the same real
   resource — the declared database attached to the declared security group,
   and the observed database attached to the observed security group —
   reconcile to CONFIRMED once the scan's identity mappings join the two
   worlds, in both namespaces, with the mapping evidence on the finding.
2. **No name matching.** A runtime-observed attachment the state never
   declared stays UNDOCUMENTED, even though the declared world contains
   similarly named resources.
3. **The snapshot boundary.** CloudTrail and IAM evidence from an older scan
   cannot influence a newer scan's findings: after a second, narrower scan,
   the older run's conclusions are gone from both the report and the store.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from reality.adapters.aws_resources import AwsResourcesAdapter
from reality.config import RealityConfig
from reality.domain.enums import Conclusion, RelationshipOrigin, RelationshipType
from reality.services.reconcile import ReconcileService, finding_id
from reality.services.scan import ScanService
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

TESTS = Path(__file__).resolve().parents[1]
AWS_FIXTURES = TESTS / "fixtures" / "aws"
IAM_FIXTURES = TESTS / "fixtures" / "iam"
CLOUDTRAIL_FIXTURES = TESTS / "fixtures" / "cloudtrail"
TF_STATE = TESTS / "fixtures" / "terraform" / "state.json"

PROFILE = "sandbox"
REGION = "eu-west-1"
ACCOUNT = "123456789012"
START = datetime(2026, 3, 1, 0, 0, tzinfo=UTC)
END = datetime(2026, 3, 2, 0, 0, tzinfo=UTC)

# Declared identities (terraform namespace) and observed identities (aws
# namespace) for the same real resources.
TF_WEB_SG = "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
TF_PRIMARY = "terraform/aws/aws_db_instance/-/-/aws_db_instance.primary"
WEB = f"aws/ec2/instance/{REGION}/{ACCOUNT}/i-0web"
WEB_SG = f"aws/ec2/security-group/{REGION}/{ACCOUNT}/sg-0aaa111"
# A security group the observed web instance attaches to but the state never
# declares: the runtime-observed legacy dependency.
OTHER_SG = f"aws/ec2/security-group/{REGION}/{ACCOUNT}/sg-0zzz999"
RDS_PRIMARY = f"aws/rds/db/{REGION}/{ACCOUNT}/primary"
PROCESSOR_ROLE = f"aws/iam/role/-/{ACCOUNT}/processor_role"
DATA_LAKE_REFERENCED = "aws/s3/bucket/-/-/data-lake"

# The finding IDs the legacy CloudTrail and IAM evidence produced in the
# first scan's pass — the ones a newer snapshot must not keep.
LEGACY_CLOUDTRAIL_FINDING = finding_id(
    PROCESSOR_ROLE, DATA_LAKE_REFERENCED, RelationshipType.DEPENDS_ON
)
LEGACY_IAM_FINDING = finding_id(
    PROCESSOR_ROLE, DATA_LAKE_REFERENCED, RelationshipType.PERMISSION_ON
)
# The finding IDs for the identity-joined database attachment.
DECLARED_DB_FINDING = finding_id(TF_PRIMARY, TF_WEB_SG, RelationshipType.ATTACHED_TO)
OBSERVED_DB_FINDING = finding_id(RDS_PRIMARY, WEB_SG, RelationshipType.ATTACHED_TO)
# Mapping evidence IDs, by the scan's deterministic scheme.
MAPPING_DB_EVIDENCE = f"identity:{TF_PRIMARY}:{RDS_PRIMARY}"
MAPPING_SG_EVIDENCE = f"identity:{TF_WEB_SG}:{WEB_SG}"

# The union of every operation the four sources' adapters may issue.
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


def resources_script() -> dict[str, dict[str, list[Any]]]:
    """The AWS resources side only: identity plus the five services."""
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


def full_script() -> dict[str, dict[str, list[Any]]]:
    """The combined script: AWS resources, IAM roles, CloudTrail events."""
    return {
        **resources_script(),
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


def full_scan(store: ScanStore) -> None:
    """Run one scan over every source: state, AWS, IAM, and CloudTrail."""
    config = RealityConfig(aws_opt_in=True, aws_profile=PROFILE, aws_region=REGION)
    ScanService.from_config(
        config,
        store,
        cloudtrail_window=(START, END),
        client_factory=FakeClientFactory(full_script()),
    ).run([TF_STATE])


def resources_scan(store: ScanStore) -> None:
    """Run a narrower scan: the state and the AWS resources side only."""
    ScanService(
        store,
        aws_resources=AwsResourcesAdapter(
            profile=PROFILE, region=REGION, client_factory=FakeClientFactory(resources_script())
        ),
        region=REGION,
    ).run([TF_STATE])


@pytest.fixture()
def store(tmp_path: Path) -> ScanStore:
    conn = connect(tmp_path / "reconciliation.db")
    migrate(conn)
    yield ScanStore(conn)
    conn.close()


# --- proof 1: terraform and aws evidence join into CONFIRMED ------------------


def test_terraform_and_aws_evidence_for_one_resource_confirm(store: ScanStore) -> None:
    full_scan(store)
    report = ReconcileService(store).run()

    conclusions = {item.finding_id: item for item in report.findings}
    # The declared database's attachment and the observed database's
    # attachment are the same real dependency: the identity mappings joined
    # them, and each namespace keeps its own CONFIRMED finding.
    assert conclusions[DECLARED_DB_FINDING].conclusion is Conclusion.CONFIRMED
    assert conclusions[OBSERVED_DB_FINDING].conclusion is Conclusion.CONFIRMED
    for finding_id_ in (DECLARED_DB_FINDING, OBSERVED_DB_FINDING):
        item = conclusions[finding_id_]
        # The mapping evidence is part of the conclusion's basis.
        assert MAPPING_DB_EVIDENCE in item.evidence_ids
        assert MAPPING_SG_EVIDENCE in item.evidence_ids
        assert "identity mapping" in item.explanation

    # The mapping evidence rows exist and carry both identities.
    db_evidence = store.evidence.get(MAPPING_DB_EVIDENCE)
    assert db_evidence is not None
    assert db_evidence.source_canonical_id == TF_PRIMARY
    assert db_evidence.target_canonical_id == RDS_PRIMARY


# --- proof 2: the legacy observed dependency stays UNDOCUMENTED ----------------


def test_runtime_observed_legacy_dependency_stays_undocumented(store: ScanStore) -> None:
    full_scan(store)
    report = ReconcileService(store).run()

    # The observed web instance also attaches to sg-0zzz999, which no state
    # resource declares — and no mapping exists that could pull a declaration
    # over it. Similar names prove nothing: the finding is UNDOCUMENTED.
    legacy = finding_id(WEB, OTHER_SG, RelationshipType.ATTACHED_TO)
    conclusions = {item.finding_id: item.conclusion for item in report.findings}
    assert conclusions[legacy] is Conclusion.UNDOCUMENTED
    assert (
        "missing rather than unread"
        in next(item for item in report.findings if item.finding_id == legacy).explanation
    )

    # And the unmapped web instance itself: its declared counterpart names a
    # different instance ID (i-0abc123def456, not i-0web), so its observed
    # attachment is UNDOCUMENTED too — nothing joined them.
    assert conclusions[finding_id(WEB, WEB_SG, RelationshipType.ATTACHED_TO)] is (
        Conclusion.UNDOCUMENTED
    )


# --- proof 3: older scan data cannot affect a newer scan ----------------------


def test_older_scan_data_cannot_affect_a_newer_scan(store: ScanStore) -> None:
    full_scan(store)  # run 1: sees CloudTrail usage and IAM permissions
    first = ReconcileService(store).run()
    assert {item.finding_id: item.conclusion for item in first.findings}[
        LEGACY_CLOUDTRAIL_FINDING
    ] is Conclusion.UNDOCUMENTED
    assert {item.finding_id: item.conclusion for item in first.findings}[
        LEGACY_IAM_FINDING
    ] is Conclusion.POSSIBLE

    resources_scan(store)  # run 2: the state and AWS resources only
    second = ReconcileService(store).run()
    assert second.analysed_scan_run_id == 3  # run 1 scanned, run 2 reconciled, run 3 scanned

    # The legacy findings are neither reported nor merely hidden: they are
    # deleted, so the older scan's evidence cannot keep them alive.
    reported = {item.finding_id for item in second.findings}
    assert LEGACY_CLOUDTRAIL_FINDING not in reported
    assert LEGACY_IAM_FINDING not in reported
    assert store.findings.get(LEGACY_CLOUDTRAIL_FINDING) is None
    assert store.findings.get(LEGACY_IAM_FINDING) is None

    # The older evidence rows themselves are untouched — history is preserved,
    # just excluded from the newer snapshot's analysis.
    assert any(
        relationship.origin is RelationshipOrigin.CLOUDTRAIL
        for relationship in store.relationships.all()
    )
    assert not any(
        relationship.origin is RelationshipOrigin.CLOUDTRAIL
        for relationship in store.relationships.for_scan_run(3)
    )

    # What run 2 did re-observe is still analysed: the joined database
    # attachment stays CONFIRMED in the newer snapshot.
    conclusions = {item.finding_id: item.conclusion for item in second.findings}
    assert conclusions[OBSERVED_DB_FINDING] is Conclusion.CONFIRMED
    assert conclusions[DECLARED_DB_FINDING] is Conclusion.CONFIRMED
