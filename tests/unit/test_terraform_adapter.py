"""Tests for the read-only Terraform JSON adapter.

All parsing is offline and pagination-independent: the adapter only reads
files the caller supplies. One test enforces the safety property directly —
the adapter source contains no subprocess usage whatsoever.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from reality.adapters.base import AdapterError
from reality.adapters.terraform import TerraformAdapter
from reality.domain.enums import (
    ChangeAction,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipType,
    ResourceType,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"

WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"
WEB_SG = "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
BATCH = "terraform/aws/aws_instance/-/-/aws_instance.batch"
ROLE = "terraform/aws/aws_iam_role/-/-/aws_iam_role.processor_role"
LAMBDA = "terraform/aws/aws_lambda_function/-/-/aws_lambda_function.processor"


@pytest.fixture
def adapter() -> TerraformAdapter:
    return TerraformAdapter()


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def resource_by_address(result, address: str):
    return next(r for r in result.resources if r.terraform_address == address)


def relationship(result, source: str, target: str, rel_type: RelationshipType):
    return next(
        rel
        for rel in result.relationships
        if rel.source_canonical_id == source
        and rel.target_canonical_id == target
        and rel.type == rel_type
    )


# --- declared resources ------------------------------------------------------


def test_state_emits_declared_resources_for_supported_types(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    by_type: dict[ResourceType, int] = {}
    for resource in result.resources:
        by_type[resource.resource_type] = by_type.get(resource.resource_type, 0) + 1
    assert by_type[ResourceType.EC2_INSTANCE] == 2  # web + batch
    assert by_type[ResourceType.SECURITY_GROUP] == 2  # web_sg + module.network.db_sg
    assert by_type[ResourceType.LAMBDA_FUNCTION] == 1
    assert by_type[ResourceType.RDS_DB_INSTANCE] == 1
    assert by_type[ResourceType.S3_BUCKET] == 1
    assert by_type[ResourceType.IAM_ROLE] == 1


def test_state_records_unsupported_types_as_terraform_resource(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    cdn = resource_by_address(result, "aws_cloudfront_distribution.cdn")
    assert cdn.resource_type == ResourceType.TERRAFORM_RESOURCE
    assert cdn.native_id == "E2ABCDEF123"  # declaration still preserved


def test_state_preserves_native_id_and_arn(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    web = resource_by_address(result, "aws_instance.web")
    assert web.native_id == "i-0abc123def456"
    assert web.arn == "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456"
    assert web.terraform_address == "aws_instance.web"


def test_declared_resources_live_in_the_terraform_namespace(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    web = resource_by_address(result, "aws_instance.web")
    assert web.canonical_id == WEB
    assert web.provider == "terraform"


def test_state_walks_child_modules(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    db_sg = resource_by_address(result, "module.network.aws_security_group.db_sg")
    assert db_sg.native_id == "sg-0bbb222"
    assert (
        db_sg.canonical_id
        == "terraform/aws/aws_security_group/-/-/module.network.aws_security_group.db_sg"
    )


def test_address_map_covers_every_declared_resource(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    assert len(result.address_map) == len(result.resources)
    assert result.address_map["aws_instance.web"] == WEB
    assert result.address_map["module.network.aws_security_group.db_sg"] == (
        "terraform/aws/aws_security_group/-/-/module.network.aws_security_group.db_sg"
    )


# --- address-to-resource resolution and declared links -----------------------


def test_explicit_depends_on_resolves_to_declared_resource(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    rel = relationship(result, WEB, WEB_SG, RelationshipType.REFERENCES)
    assert rel.evidence_ids  # backed by evidence


def test_security_group_attachment_resolves_via_native_id(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    rel = relationship(result, WEB, WEB_SG, RelationshipType.ATTACHED_TO)
    assert rel.source_canonical_id == WEB
    assert rel.target_canonical_id == WEB_SG


def test_lambda_role_attachment_resolves_via_declared_arn(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    rel = relationship(result, LAMBDA, ROLE, RelationshipType.PERMISSION_ON)
    assert rel.target_canonical_id == ROLE


def test_instance_profile_resolves_through_arn_parsing(adapter) -> None:
    # The instance profile is not declared anywhere in the fixture, but the
    # reference is a fully-qualified ARN, so it resolves in the AWS namespace.
    result = adapter.parse_document(load_fixture("state.json"))
    rel = next(
        rel
        for rel in result.relationships
        if rel.source_canonical_id == WEB
        and rel.target_canonical_id == "aws/iam/instance-profile/-/123456789012/web-profile"
    )
    assert rel.type == RelationshipType.REFERENCES


def test_undeclared_native_reference_stays_unresolved(adapter) -> None:
    # sg-0undeclared is region-scoped with no region context available here;
    # the adapter must not guess an account or region to force a join.
    result = adapter.parse_document(load_fixture("state.json"))
    rel = next(
        rel
        for rel in result.relationships
        if rel.source_canonical_id == BATCH and rel.type == RelationshipType.ATTACHED_TO
    )
    assert rel.target_canonical_id == "unresolved/-/-/-/-/sg-0undeclared"


def test_depends_on_to_undeclared_address_parses_to_terraform_id(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    bucket = "terraform/aws/aws_s3_bucket/-/-/aws_s3_bucket.data"
    rel = relationship(
        result,
        bucket,
        "terraform/aws/aws_kms_key/-/-/aws_kms_key.key",
        RelationshipType.REFERENCES,
    )
    assert rel.target_canonical_id.startswith("terraform/")


# --- evidence ----------------------------------------------------------------


def test_every_relationship_is_backed_by_evidence(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"), source_path="state.json")
    evidence_by_id = {item.id: item for item in result.evidence}
    assert len(evidence_by_id) == len(result.evidence)  # IDs are unique
    for rel in result.relationships:
        assert rel.evidence_ids
        for evidence_id in rel.evidence_ids:
            evidence = evidence_by_id[evidence_id]
            assert evidence.source == EvidenceSource.TERRAFORM_STATE
            assert evidence.type == EvidenceType.CONFIG_REFERENCE
            assert evidence.actor == "terraform"
            assert evidence.explanation
            assert "state.json#" in evidence.raw_locator  # points back at the source
            assert evidence.source_canonical_id == rel.source_canonical_id
            assert evidence.target_canonical_id == rel.target_canonical_id


def test_evidence_strength_differs_for_explicit_vs_inferred(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"))
    by_strength = {item.strength for item in result.evidence}
    assert EvidenceStrength.HIGH in by_strength  # explicit depends_on
    assert EvidenceStrength.MEDIUM in by_strength  # inferred attribute links


def test_evidence_ids_are_deterministic(adapter) -> None:
    first = adapter.parse_document(load_fixture("state.json"))
    second = adapter.parse_document(load_fixture("state.json"))
    assert {item.id for item in first.evidence} == {item.id for item in second.evidence}


# --- coverage and safe errors -------------------------------------------------


def test_state_emits_available_coverage(adapter) -> None:
    result = adapter.parse_document(load_fixture("state.json"), source_path="state.json")
    assert len(result.coverage) == 1
    coverage = result.coverage[0]
    assert coverage.source == EvidenceSource.TERRAFORM_STATE
    assert coverage.status == CoverageStatus.AVAILABLE
    assert "9 declared resources" in coverage.reason


def test_empty_state_is_available_but_empty(adapter) -> None:
    result = adapter.parse_document({"format_version": "1.0", "values": None})
    assert result.resources == ()
    assert result.coverage[0].status == CoverageStatus.AVAILABLE
    assert "empty state" in result.coverage[0].reason


def test_malformed_state_identifies_json_path(adapter) -> None:
    with pytest.raises(AdapterError) as exc_info:
        adapter.parse_document(load_fixture("malformed.json"))
    assert exc_info.value.json_path == "$.values.root_module.resources[0].address"
    assert "address" in exc_info.value.message


def test_parse_file_returns_unavailable_coverage_for_malformed_input(adapter) -> None:
    result = adapter.parse_file(FIXTURES / "malformed.json")
    assert result.resources == ()
    assert result.relationships == ()
    coverage = result.coverage[0]
    assert coverage.status == CoverageStatus.UNAVAILABLE
    assert "$.values.root_module.resources[0].address" in coverage.reason


def test_parse_file_returns_unavailable_coverage_for_invalid_json(adapter, tmp_path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    result = adapter.parse_file(bad)
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "invalid JSON" in result.coverage[0].reason


def test_parse_file_reports_unreadable_file(adapter, tmp_path) -> None:
    result = adapter.parse_file(tmp_path / "does-not-exist.json")
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "could not read" in result.coverage[0].reason


def test_rejects_documents_that_are_neither_state_nor_plan(adapter) -> None:
    with pytest.raises(AdapterError) as exc_info:
        adapter.parse_document({"format_version": "1.0"})
    assert exc_info.value.json_path == "$"


def test_malformed_plan_actions_identify_their_path(adapter) -> None:
    document = {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {"actions": ["explode"]},
            }
        ]
    }
    with pytest.raises(AdapterError) as exc_info:
        adapter.parse_document(document)
    assert exc_info.value.json_path == "$.resource_changes[0].change.actions[0]"


# --- plan change classification ------------------------------------------------


def test_plan_delete_is_classified(adapter) -> None:
    result = adapter.parse_document(load_fixture("plan_delete.json"))
    by_address = {change.address: change for change in result.terraform_changes}
    assert by_address["aws_db_instance.primary"].actions == (ChangeAction.DELETE,)
    assert by_address["aws_security_group.web_sg"].actions == (ChangeAction.NOOP,)


def test_plan_delete_does_not_apply_anything(adapter) -> None:
    # The delete plan still emits declared resources from planned_values;
    # it never removes, marks, or proposes anything.
    result = adapter.parse_document(load_fixture("plan_delete.json"))
    surviving = resource_by_address(result, "aws_security_group.web_sg")
    assert surviving.native_id == "sg-0aaa111"
    deleted = [r for r in result.resources if r.terraform_address == "aws_db_instance.primary"]
    assert deleted == []


def test_plan_replacement_is_classified_as_replace(adapter) -> None:
    result = adapter.parse_document(load_fixture("plan_replace.json"))
    by_address = {change.address: change for change in result.terraform_changes}
    assert by_address["aws_instance.web"].actions == (ChangeAction.REPLACE,)
    assert by_address["aws_lambda_function.processor"].actions == (ChangeAction.UPDATE,)
    for change in result.terraform_changes:
        assert change.canonical_id.startswith("terraform/")


def test_plan_coverage_mentions_change_count(adapter) -> None:
    result = adapter.parse_document(load_fixture("plan_replace.json"), source_path="plan.json")
    coverage = result.coverage[0]
    assert coverage.source == EvidenceSource.TERRAFORM_PLAN
    assert coverage.status == CoverageStatus.AVAILABLE
    assert "2 changes" in coverage.reason


# --- unknown values ------------------------------------------------------------


def test_unknown_values_are_preserved_not_guessed(adapter) -> None:
    result = adapter.parse_document(load_fixture("plan_unknown.json"))
    # The lambda's ARN is unknown at plan time: no fabricated value.
    fn = resource_by_address(result, "aws_lambda_function.processor")
    assert fn.native_id == "processor"
    assert fn.arn is None
    # The role reference is deferred: the link is kept, the target unresolved.
    rel = next(rel for rel in result.relationships if rel.source_canonical_id == LAMBDA)
    assert rel.target_canonical_id.startswith("unresolved/")
    evidence = next(e for e in result.evidence if e.id in rel.evidence_ids)
    assert evidence.strength == EvidenceStrength.UNKNOWN
    assert evidence.target_ref == "(known after apply)"
    assert "unknown" in evidence.explanation


def test_unknown_instance_id_in_replacement_plan_is_not_fabricated(adapter) -> None:
    result = adapter.parse_document(load_fixture("plan_replace.json"))
    web = resource_by_address(result, "aws_instance.web")
    assert web.native_id is None  # "(unknown)" in the plan
    assert web.arn is None


# --- safety: no subprocess, no terraform execution ------------------------------


def test_adapter_source_contains_no_subprocess_usage() -> None:
    # Walk the AST: only executed code counts, docstrings may say anything.
    import ast

    from reality.adapters import terraform as terraform_module

    tree = ast.parse(inspect.getsource(terraform_module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all("subprocess" not in alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or "subprocess" not in node.module
        elif isinstance(node, ast.Call):
            called = node.func
            name = getattr(called, "attr", None) or getattr(called, "id", None)
            assert name not in {
                "system",
                "popen",
                "Popen",
                "run",
                "check_output",
                "check_call",
            }, f"adapter must not call {name!r}"


def test_collect_reads_a_file_and_returns_the_same_result(adapter) -> None:
    via_collect = adapter.collect(FIXTURES / "state.json")
    via_parse = adapter.parse_file(FIXTURES / "state.json")

    # Coverage recorded_at and Resource discovered_at are stamped per call and
    # can straddle a clock tick between the two parses; everything else must
    # match exactly.
    def without_timestamps(resources):
        return [resource.model_dump(exclude={"discovered_at"}) for resource in resources]

    assert without_timestamps(via_collect.resources) == without_timestamps(via_parse.resources)
    assert via_collect.relationships == via_parse.relationships
    assert via_collect.evidence == via_parse.evidence
    assert via_collect.address_map == via_parse.address_map
    assert via_collect.terraform_changes == via_parse.terraform_changes
