"""Fixture-driven tests for the domain models: validation and round trips."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from reality.domain.enums import (
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    ImpactBasis,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.ids import parse_arn, parse_terraform_address
from reality.domain.models import (
    Coverage,
    Evidence,
    Finding,
    ImpactItem,
    ImpactResult,
    Relationship,
    Resource,
    TerraformChange,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ids" / "cases.json"


def _sample_resource() -> Resource:
    return Resource(
        canonical_id=parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456").key,
        resource_type=ResourceType.EC2_INSTANCE,
        provider="aws",
        native_id="i-0abc123def456",
        arn="arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456",
        region="eu-west-1",
        account="123456789012",
        name="web-server",
        source=EvidenceSource.AWS_RESOURCES,
    )


def _sample_evidence() -> Evidence:
    return Evidence(
        id="ev-0001",
        source=EvidenceSource.CLOUDTRAIL,
        type=EvidenceType.API_EVENT,
        observed_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
        actor="arn:aws:iam::123456789012:role/deploy-role",
        source_ref="arn:aws:iam::123456789012:role/deploy-role",
        target_ref="arn:aws:s3:::acme-customer-data",
        source_canonical_id=parse_arn("arn:aws:iam::123456789012:role/deploy-role").key,
        target_canonical_id=parse_arn("arn:aws:s3:::acme-customer-data").key,
        strength=EvidenceStrength.HIGH,
        raw_locator="cloudtrail:eventId:0f4a",
        explanation="PutObject API call observed in CloudTrail management/data events",
    )


# --- Resource ---------------------------------------------------------------


def test_resource_requires_the_core_fields() -> None:
    resource = _sample_resource()
    assert resource.resource_type == ResourceType.EC2_INSTANCE
    # Source-native identity preserved alongside the canonical key.
    assert resource.native_id == "i-0abc123def456"
    assert resource.arn == "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456"
    assert resource.canonical_id != resource.native_id


def test_resource_requires_canonical_id_and_type() -> None:
    with pytest.raises(ValidationError):
        Resource(canonical_id="", resource_type=ResourceType.EC2_INSTANCE, provider="aws")
    with pytest.raises(ValidationError):
        Resource(canonical_id="x/y", provider="aws")


def test_resource_is_immutable() -> None:
    resource = _sample_resource()
    with pytest.raises(Exception, match="frozen"):
        resource.name = "renamed"  # type: ignore[misc]


def test_resource_defaults_are_neutral() -> None:
    resource = Resource(
        canonical_id="terraform/aws/aws_instance/-/-/aws_instance.web",
        resource_type=ResourceType.TERRAFORM_RESOURCE,
        provider="terraform",
        terraform_address="aws_instance.web",
    )
    assert resource.native_id is None
    assert resource.arn is None
    assert resource.source is None


# --- Relationship -----------------------------------------------------------


def test_relationship_links_evidence_without_concluding() -> None:
    rel = Relationship(
        source_canonical_id=parse_arn(
            "arn:aws:lambda:us-east-1:123456789012:function:process-orders"
        ).key,
        target_canonical_id=parse_arn("arn:aws:s3:::acme-customer-data").key,
        type=RelationshipType.PERMISSION_ON,
        origin=RelationshipOrigin.IAM_POLICY,
        first_seen_at=datetime(2026, 9, 1, tzinfo=UTC),
        last_seen_at=datetime(2026, 9, 2, tzinfo=UTC),
        evidence_ids=("ev-0001",),
    )
    assert rel.evidence_ids == ("ev-0001",)
    # A relationship is a candidate, never a conclusion.
    assert not hasattr(rel, "conclusion")


def test_relationship_rejects_empty_evidence_tuple_fields_but_allows_empty() -> None:
    rel = Relationship(
        source_canonical_id="a",
        target_canonical_id="b",
        type=RelationshipType.DEPENDS_ON,
        origin=RelationshipOrigin.TERRAFORM_DECLARED,
    )
    assert rel.evidence_ids == ()
    assert rel.first_seen_at is None


def test_relationship_is_immutable() -> None:
    rel = Relationship(
        source_canonical_id="a",
        target_canonical_id="b",
        type=RelationshipType.DEPENDS_ON,
        origin=RelationshipOrigin.SIMULATION,
    )
    with pytest.raises(Exception, match="frozen"):
        rel.type = RelationshipType.CONTAINS  # type: ignore[misc]


# --- Evidence ---------------------------------------------------------------


def test_evidence_retains_every_required_field() -> None:
    evidence = _sample_evidence()
    assert evidence.id == "ev-0001"
    assert evidence.source == EvidenceSource.CLOUDTRAIL
    assert evidence.type == EvidenceType.API_EVENT
    assert evidence.observed_at == datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    assert evidence.actor is not None and "deploy-role" in evidence.actor
    assert evidence.source_ref.endswith("deploy-role")
    assert evidence.target_ref.endswith("acme-customer-data")
    assert evidence.strength == EvidenceStrength.HIGH
    assert "cloudtrail" in evidence.raw_locator
    assert evidence.explanation


def test_evidence_requires_source_and_target_refs() -> None:
    with pytest.raises(ValidationError):
        Evidence(  # type: ignore[call-arg]
            id="ev-0002",
            source=EvidenceSource.IAM,
            type=EvidenceType.POLICY_STATEMENT,
            strength=EvidenceStrength.LOW,
            raw_locator="policy.json#/Statement/0",
            explanation="policy grants s3:GetObject",
        )


def test_evidence_strength_is_qualitative() -> None:
    # No numeric confidence anywhere: strength is an enum of four values.
    assert {s.value for s in EvidenceStrength} == {"high", "medium", "low", "unknown"}


def test_evidence_serialization_round_trip() -> None:
    evidence = _sample_evidence()
    restored = Evidence.model_validate_json(evidence.model_dump_json())
    assert restored == evidence


# --- Coverage ---------------------------------------------------------------


def test_coverage_status_enumerates_exactly_three_states() -> None:
    assert {s.value for s in CoverageStatus} == {"available", "unavailable", "not_requested"}


def test_coverage_requires_reason() -> None:
    coverage = Coverage(
        source=EvidenceSource.CLOUDTRAIL,
        status=CoverageStatus.UNAVAILABLE,
        reason="LookupEvents only retains the last 90 days",
        region="eu-west-1",
    )
    assert coverage.status == CoverageStatus.UNAVAILABLE
    with pytest.raises(ValidationError):
        Coverage(  # type: ignore[call-arg]
            source=EvidenceSource.CLOUDTRAIL, status=CoverageStatus.AVAILABLE
        )


def test_coverage_serialization_round_trip() -> None:
    coverage = Coverage(
        source=EvidenceSource.TERRAFORM_PLAN,
        status=CoverageStatus.NOT_REQUESTED,
        reason="scan phase only requested AWS and IAM",
    )
    assert Coverage.model_validate_json(coverage.model_dump_json()) == coverage


# --- TerraformChange --------------------------------------------------------


@pytest.mark.parametrize(
    "actions,expected",
    [
        (["create"], ("create",)),
        (["delete", "create"], ("delete", "create")),
        (["no-op"], ("noop",)),
        (["update"], ("update",)),
        (["delete", "create"], ("delete", "create")),
    ],
)
def test_terraform_change_parses_raw_plan_actions(actions: list, expected: tuple) -> None:
    from reality.domain.enums import ChangeAction

    change = TerraformChange(
        address="aws_instance.web",
        tf_resource_type="aws_instance",
        actions=tuple(ChangeAction(a.replace("no-op", "noop")) for a in actions),
        canonical_id=parse_terraform_address("aws_instance.web").key,
    )
    assert change.actions == expected
    assert change.address == "aws_instance.web"


def test_terraform_change_requires_actions() -> None:
    with pytest.raises(ValidationError):
        TerraformChange(address="aws_instance.web", tf_resource_type="aws_instance", actions=())


# --- Finding ----------------------------------------------------------------


def test_finding_conclusion_semantics_are_the_frozen_five() -> None:
    assert {c.value for c in Conclusion} == {
        "confirmed",
        "undocumented",
        "possible",
        "declared_only",
        "unknown",
    }


def test_finding_tracks_unavailable_sources_for_unknown() -> None:
    finding = Finding(
        id="f-0001",
        subject_canonical_id="terraform/aws/aws_instance/-/-/aws_instance.web",
        conclusion=Conclusion.UNKNOWN,
        explanation="no CloudTrail data available for the lookback window",
        unavailable_sources=(EvidenceSource.CLOUDTRAIL,),
    )
    assert finding.conclusion == Conclusion.UNKNOWN
    assert EvidenceSource.CLOUDTRAIL in finding.unavailable_sources


def test_finding_is_immutable() -> None:
    finding = Finding(
        id="f-0001",
        subject_canonical_id="a",
        conclusion=Conclusion.CONFIRMED,
        explanation="declared and observed",
    )
    with pytest.raises(Exception, match="frozen"):
        finding.conclusion = Conclusion.UNDOCUMENTED  # type: ignore[misc]


# --- ImpactResult -----------------------------------------------------------


def test_impact_result_reports_without_proposing_actions() -> None:
    subject = "aws/ec2/instance/eu-west-1/123456789012/i-0abc123def456"
    result = ImpactResult(
        subject_canonical_id=subject,
        basis=ImpactBasis.TERRAFORM_PLAN,
        affected=(
            ImpactItem(canonical_id=subject, path=(subject,), depth=1),
            ImpactItem(
                canonical_id="aws/s3/bucket/-/-/acme-customer-data",
                path=(subject, "aws/s3/bucket/-/-/acme-customer-data"),
                depth=2,
            ),
        ),
        notes=("1 target outside provider scope could not be resolved",),
    )
    assert len(result.affected) == 2
    assert result.affected[1].depth == 2
    # A report, not an action: no proposed remediation, no deletion list.
    assert not any("delete" in n or "apply" in n for n in result.notes)


def test_impact_item_depth_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        ImpactItem(canonical_id="a", path=("a",), depth=0)


def test_impact_result_serialization_round_trip() -> None:
    result = ImpactResult(
        subject_canonical_id="a",
        basis=ImpactBasis.DISCOVERY_GRAPH,
        affected=(ImpactItem(canonical_id="a", path=("a",), depth=1),),
    )
    assert ImpactResult.model_validate_json(result.model_dump_json()) == result


# --- Cross-model round trips ------------------------------------------------


def test_all_models_round_trip_through_json() -> None:
    subject = _sample_resource()
    evidence = _sample_evidence()
    objects = [
        subject,
        evidence,
        Relationship(
            source_canonical_id=evidence.source_canonical_id or "",
            target_canonical_id=evidence.target_canonical_id or "",
            type=RelationshipType.PERMISSION_ON,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_ids=(evidence.id,),
        ),
        Finding(
            id="f-0001",
            subject_canonical_id=subject.canonical_id,
            conclusion=Conclusion.CONFIRMED,
            explanation="declared and observed",
            evidence_ids=(evidence.id,),
        ),
    ]
    for obj in objects:
        restored = type(obj).model_validate_json(obj.model_dump_json())
        assert restored == obj


def test_json_dump_is_valid_json_and_enums_serialize_as_values() -> None:
    evidence = _sample_evidence()
    payload = json.loads(evidence.model_dump_json())
    assert payload["source"] == "cloudtrail"
    assert payload["strength"] == "high"
