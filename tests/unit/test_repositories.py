"""Tests for repository semantics: idempotency, temporal fields, JSON, rollback."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from reality.domain.enums import (
    ChangeAction,
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.models import (
    Coverage,
    Evidence,
    Finding,
    Relationship,
    Resource,
    TerraformChange,
)
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

T0 = datetime(2026, 9, 1, tzinfo=UTC)
T1 = datetime(2026, 9, 10, tzinfo=UTC)
T2 = datetime(2026, 9, 20, tzinfo=UTC)

INSTANCE_KEY = "aws/ec2/instance/eu-west-1/123456789012/i-0abc123def456"
ROLE_KEY = "aws/iam/role/-/123456789012/deploy-role"
BUCKET_KEY = "aws/s3/bucket/-/-/acme-customer-data"


@pytest.fixture
def store(tmp_path) -> ScanStore:
    conn = connect(tmp_path / "evidence.db")
    migrate(conn)
    return ScanStore(conn)


def make_resource(**overrides) -> Resource:
    fields = dict(
        canonical_id=INSTANCE_KEY,
        resource_type=ResourceType.EC2_INSTANCE,
        provider="aws",
        native_id="i-0abc123def456",
        region="eu-west-1",
        account="123456789012",
        discovered_at=T0,
        source=EvidenceSource.AWS_RESOURCES,
    )
    fields.update(overrides)
    return Resource(**fields)


def make_evidence(**overrides) -> Evidence:
    fields = dict(
        id="ev-0001",
        source=EvidenceSource.CLOUDTRAIL,
        type=EvidenceType.API_EVENT,
        observed_at=T1,
        actor="arn:aws:iam::123456789012:role/deploy-role",
        source_ref="arn:aws:iam::123456789012:role/deploy-role",
        target_ref="arn:aws:s3:::acme-customer-data",
        source_canonical_id=ROLE_KEY,
        target_canonical_id=BUCKET_KEY,
        strength=EvidenceStrength.HIGH,
        raw_locator="cloudtrail:eventId:0f4a",
        explanation="PutObject observed",
    )
    fields.update(overrides)
    return Evidence(**fields)


def make_relationship(**overrides) -> Relationship:
    fields = dict(
        source_canonical_id=ROLE_KEY,
        target_canonical_id=BUCKET_KEY,
        type=RelationshipType.PERMISSION_ON,
        origin=RelationshipOrigin.IAM_POLICY,
        first_seen_at=T0,
        last_seen_at=T0,
    )
    fields.update(overrides)
    return Relationship(**fields)


# --- scan runs and the transaction boundary ---------------------------------


def test_scan_creates_and_finishes_a_run(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.AWS_RESOURCES, region="eu-west-1") as session:
        session.upsert_resource(make_resource())
    row = store.conn.execute("SELECT * FROM scan_runs").fetchone()
    assert row["source"] == "aws_resources"
    assert row["region"] == "eu-west-1"
    assert row["finished_at"] is not None


def test_scan_rolls_back_everything_on_error(store: ScanStore) -> None:
    class Boom(Exception):
        pass

    with pytest.raises(Boom), store.scan(source=EvidenceSource.AWS_RESOURCES):
        # Deliberately write rows inside the failing scan.
        store.conn.execute(
            "INSERT INTO resources (canonical_id, resource_type, provider, discovered_at) "
            "VALUES ('sneaky', 'ec2_instance', 'aws', '2026-01-01T00:00:00+00:00')"
        )
        raise Boom()
    assert store.scan_runs.count() == 0
    assert store.resources.count() == 0


def test_successful_scans_accumulate(store: ScanStore) -> None:
    for _ in range(2):
        with store.scan(source=EvidenceSource.AWS_RESOURCES) as session:
            session.upsert_resource(make_resource())
    assert store.scan_runs.count() == 2
    assert store.resources.count() == 1  # same resource, upserted


# --- resources --------------------------------------------------------------


def test_resource_upsert_is_idempotent(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.AWS_RESOURCES) as session:
        session.upsert_resource(make_resource())
        session.upsert_resource(make_resource())
    assert store.resources.count() == 1


def test_resource_discovered_at_is_never_overwritten(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.AWS_RESOURCES) as session:
        session.upsert_resource(make_resource(discovered_at=T0))
    with store.scan(source=EvidenceSource.TERRAFORM_STATE) as session:
        session.upsert_resource(make_resource(discovered_at=T2))  # later discovery
    assert store.resources.get(INSTANCE_KEY).discovered_at == T0


def test_resource_merge_fills_gaps_without_blanking(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.AWS_RESOURCES) as session:
        session.upsert_resource(make_resource(name="web"))
    with store.scan(source=EvidenceSource.TERRAFORM_STATE) as session:
        # Second source knows the ARN but not the name.
        session.upsert_resource(
            make_resource(
                name=None, arn="arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456"
            )
        )
    merged = store.resources.get(INSTANCE_KEY)
    assert merged.name == "web"  # not blanked
    assert merged.arn is not None  # filled in


def test_resource_round_trips_domain_model(store: ScanStore) -> None:
    original = make_resource(name="web-server")
    with store.scan(source=EvidenceSource.AWS_RESOURCES) as session:
        session.upsert_resource(original)
    assert store.resources.get(INSTANCE_KEY) == original


# --- evidence ---------------------------------------------------------------


def test_evidence_upsert_is_idempotent(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.upsert_evidence(make_evidence())
        session.upsert_evidence(make_evidence())
    assert store.evidence.count() == 1


def test_evidence_round_trips_domain_model(store: ScanStore) -> None:
    original = make_evidence()
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.upsert_evidence(original)
    assert store.evidence.get("ev-0001") == original


def test_evidence_raw_json_round_trips(store: ScanStore) -> None:
    payload = {
        "eventID": "0f4a",
        "eventName": "PutObject",
        "requestParameters": {"bucketName": "acme-customer-data", "key": "orders/1.json"},
        "nested": {"list": [1, 2, {"deep": True}]},
    }
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.upsert_evidence(make_evidence(), raw_payload=payload)
    record = store.evidence.get_record("ev-0001")
    assert record.raw_payload == payload


def test_evidence_raw_json_absent_when_not_supplied(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.upsert_evidence(make_evidence())  # no raw_payload argument
    record = store.evidence.get_record("ev-0001")
    assert record.raw_payload is None
    raw = store.conn.execute("SELECT raw_json FROM evidence WHERE id = 'ev-0001'").fetchone()
    assert raw["raw_json"] is None  # NULL, not the string "null"


def test_evidence_observed_at_round_trips_tz_aware(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.upsert_evidence(make_evidence(observed_at=T1 + timedelta(hours=3)))
    restored = store.evidence.get("ev-0001")
    assert restored.observed_at == T1 + timedelta(hours=3)
    assert restored.observed_at.tzinfo is not None


# --- relationships and temporal semantics -----------------------------------


def test_relationship_identity_is_stable(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        first = session.upsert_relationship(make_relationship())
    with store.scan(source=EvidenceSource.IAM) as session:
        second = session.upsert_relationship(make_relationship())
    assert first == second
    assert store.conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0] == 1


def test_relationship_distinct_identity_gets_its_own_row(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship())
        session.upsert_relationship(make_relationship(origin=RelationshipOrigin.CLOUDTRAIL))
    assert store.conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0] == 2


def test_first_seen_is_never_overwritten(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T1, last_seen_at=T1))
    with store.scan(source=EvidenceSource.IAM) as session:
        # A second observation claims an earlier first_seen; it must not rewrite.
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T2))
    relationship = store.relationships.outgoing(ROLE_KEY)[0]
    assert relationship.first_seen_at == T1


def test_first_seen_set_once_when_previously_null(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=None, last_seen_at=None))
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T0))
    relationship = store.relationships.outgoing(ROLE_KEY)[0]
    assert relationship.first_seen_at == T0


def test_last_seen_advances_only_with_later_observation(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T1))
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T2))
    assert store.relationships.outgoing(ROLE_KEY)[0].last_seen_at == T2


def test_last_seen_does_not_regress_with_earlier_observation(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T2))
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T1))
    assert store.relationships.outgoing(ROLE_KEY)[0].last_seen_at == T2


def test_last_seen_survives_null_observation(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=T1))
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_relationship(make_relationship(first_seen_at=T0, last_seen_at=None))
    assert store.relationships.outgoing(ROLE_KEY)[0].last_seen_at == T1


def test_evidence_linking_is_idempotent(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_evidence(make_evidence())
        rid = session.upsert_relationship(make_relationship(), evidence_ids=["ev-0001"])
        session.upsert_relationship(make_relationship(), evidence_ids=["ev-0001"])
    links = store.conn.execute(
        "SELECT COUNT(*) FROM relationship_evidence WHERE relationship_id = ?", (rid,)
    ).fetchone()[0]
    assert links == 1
    relationship = store.relationships.outgoing(ROLE_KEY)[0]
    assert relationship.evidence_ids == ("ev-0001",)


def test_relationship_round_trips_with_evidence_ids(store: ScanStore) -> None:
    with store.scan(source=EvidenceSource.IAM) as session:
        session.upsert_evidence(make_evidence())
        session.upsert_relationship(make_relationship(), evidence_ids=["ev-0001"])
    relationship = store.relationships.outgoing(ROLE_KEY)[0]
    assert relationship.source_canonical_id == ROLE_KEY
    assert relationship.target_canonical_id == BUCKET_KEY
    assert relationship.type == RelationshipType.PERMISSION_ON
    assert relationship.first_seen_at == T0


# --- coverage, terraform addresses, findings --------------------------------


def test_coverage_round_trips(store: ScanStore) -> None:
    coverage = Coverage(
        source=EvidenceSource.CLOUDTRAIL,
        status=CoverageStatus.UNAVAILABLE,
        reason="LookupEvents retains only 90 days",
        region="eu-west-1",
        recorded_at=T1,
    )
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.add_coverage(coverage)
    records = store.coverage.all_records()
    assert len(records) == 1
    assert records[0] == coverage


def test_terraform_change_round_trips(store: ScanStore) -> None:
    change = TerraformChange(
        address="aws_instance.web",
        tf_resource_type="aws_instance",
        actions=(ChangeAction.DELETE, ChangeAction.CREATE),
        canonical_id="terraform/aws/aws_instance/-/-/aws_instance.web",
    )
    with store.scan(source=EvidenceSource.TERRAFORM_PLAN) as session:
        session.upsert_terraform_address(change)
    assert store.terraform_addresses.get("aws_instance.web") == change


def test_finding_round_trips(store: ScanStore) -> None:
    finding = Finding(
        id="f-0001",
        subject_canonical_id=BUCKET_KEY,
        conclusion=Conclusion.UNDOCUMENTED,
        explanation="observed in CloudTrail but absent from Terraform",
        evidence_ids=("ev-0001",),
        unavailable_sources=(EvidenceSource.TERRAFORM_STATE,),
    )
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        session.upsert_finding(finding)
    assert store.findings.get("f-0001") == finding
    assert store.findings.for_subject(BUCKET_KEY) == (finding,)


# --- the why/impact read ----------------------------------------------------


def test_get_resource_context_returns_none_for_unknown(store: ScanStore) -> None:
    assert store.get_resource_context("aws/ec2/instance/eu-west-1/1/i-nope") is None


def test_get_resource_context_returns_the_full_picture(store: ScanStore) -> None:
    instance = make_resource()
    role = make_resource(
        canonical_id=ROLE_KEY,
        resource_type=ResourceType.IAM_ROLE,
        native_id="deploy-role",
        arn="arn:aws:iam::123456789012:role/deploy-role",
        region=None,
    )
    bucket = make_resource(
        canonical_id=BUCKET_KEY,
        resource_type=ResourceType.S3_BUCKET,
        native_id="acme-customer-data",
        region=None,
    )
    with store.scan(source=EvidenceSource.AWS_RESOURCES, region="eu-west-1") as session:
        session.upsert_resource(instance)
        session.upsert_resource(role)
        session.upsert_resource(bucket)
        session.upsert_evidence(make_evidence())
        session.upsert_relationship(
            make_relationship(),
            evidence_ids=["ev-0001"],
        )
        session.add_coverage(
            Coverage(
                source=EvidenceSource.CLOUDTRAIL,
                status=CoverageStatus.AVAILABLE,
                reason="LookupEvents queried for the lookback window",
                region="eu-west-1",
                recorded_at=T1,
            )
        )

    # Instance is the subject: nothing outgoing, but evidence references it?
    context = store.get_resource_context(ROLE_KEY)
    assert context.resource == role
    assert len(context.outgoing) == 1
    assert context.outgoing[0].target_canonical_id == BUCKET_KEY
    assert context.outgoing[0].evidence_ids == ("ev-0001",)
    assert context.incoming == ()
    evidence_ids = {record.evidence.id for record in context.evidence}
    assert evidence_ids == {"ev-0001"}
    assert len(context.coverage) == 1
    assert context.coverage[0].status == CoverageStatus.AVAILABLE

    # The bucket sees the same relationship as incoming.
    bucket_context = store.get_resource_context(BUCKET_KEY)
    assert bucket_context.incoming[0].source_canonical_id == ROLE_KEY
    assert bucket_context.outgoing == ()
