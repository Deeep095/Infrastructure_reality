"""Tests for the read-only IAM permission-evidence adapter.

Everything runs against fake injected clients (plus, when the optional aws
extra is installed, one botocore Stubber case). No test needs credentials, a
profile, or network access, and none can mutate anything: the fake client
refuses every operation outside the read-only List/Get whitelist. The policy
fixtures exercise every defensive parsing form — statement as object or
list, Action/Resource as scalar or list, Allow versus Deny, wildcards,
policy variables, duplicate entries, and malformed statements.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from reality.adapters.iam import ALLOWED_OPERATIONS, IamAdapter
from reality.config import ConfigError, RealityConfig
from reality.domain.enums import (
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "iam"

PROFILE = "sandbox"
REGION = "eu-west-1"

PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
CLEANUP_ROLE = "aws/iam/role/-/123456789012/cleanup_role"
AUDITOR_ROLE = "aws/iam/role/-/123456789012/auditor_role"

DATA_READER_ARN = "arn:aws:iam::123456789012:policy/DataReader"
AUDITOR_ACCESS_ARN = "arn:aws:iam::123456789012:policy/AuditorAccess"

# A bucket ARN carries no account, so the canonical target does not either;
# reconciliation may later refine it with the scan account.
DATA_LAKE = "aws/s3/bucket/-/-/data-lake"
AUDIT_LOGS = "aws/s3/bucket/-/-/audit-logs"
PROCESSED_EVENTS = "aws/dynamodb/table/eu-west-1/123456789012/processed-events"
CLEANUP_TASKS = "aws/dynamodb/table/eu-west-1/123456789012/cleanup-tasks"
AUDIT_QUEUE = "aws/sqs/resource/eu-west-1/123456789012/audit-queue"

DATA_LAKE_WILDCARD = "unresolved/-/-/-/-/arn:aws:s3:::data-lake/*"
STAR = "unresolved/-/-/-/-/*"
HOME_VARIABLE = "unresolved/-/-/-/-/arn:aws:s3:::home/${aws:username}/*"

PROCESSOR_INLINE = "arn:aws:iam::123456789012:role/processor_role/processor-inline"
DATA_READER = f"{DATA_READER_ARN}@v2"


# --- fakes: scripted clients, no boto3 required ------------------------------


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
            self.calls.append((operation, kwargs))
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


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def full_script() -> dict[str, dict[str, list[Any]]]:
    # Queues are sequential per operation; roles are processed in list order
    # (processor, cleanup, auditor), inline policies before attached ones.
    return {
        "iam": {
            "list_roles": list(load("list_roles.json")["pages"]),
            "list_role_policies": [
                *load("list_role_policies_processor.json")["pages"],
                load("list_role_policies_cleanup.json"),
                load("list_role_policies_auditor.json"),
            ],
            "get_role_policy": [
                load("get_role_policy_processor_inline.json"),
                load("get_role_policy_processor_readonly.json"),
                load("get_role_policy_cleanup_inline.json"),
                load("get_role_policy_auditor_inline.json"),
            ],
            "list_attached_role_policies": [
                load("list_attached_role_policies_processor.json"),
                load("list_attached_role_policies_cleanup.json"),
                load("list_attached_role_policies_auditor.json"),
            ],
            "get_policy": [
                load("get_policy_data_reader.json"),
                load("get_policy_auditor_access.json"),
            ],
            "get_policy_version": [
                load("get_policy_version_data_reader_v2.json"),
                load("get_policy_version_auditor_access_v1.json"),
            ],
        }
    }


def make_adapter(
    script: dict[str, dict[str, list[Any]]] | None = None,
) -> tuple[IamAdapter, FakeClientFactory]:
    factory = FakeClientFactory(script if script is not None else full_script())
    adapter = IamAdapter(profile=PROFILE, region=REGION, client_factory=factory)
    return adapter, factory


def collect_full() -> Any:
    adapter, _ = make_adapter()
    return adapter.collect()


def relationships_as_tuples(result: Any) -> set[tuple[str, str]]:
    return {(rel.source_canonical_id, rel.target_canonical_id) for rel in result.relationships}


def calls_for(factory: FakeClientFactory, operation: str) -> list[dict[str, Any]]:
    return [kwargs for op, kwargs in factory.clients["iam"].calls if op == operation]


# --- configuration gate -------------------------------------------------------


def test_blank_profile_is_rejected_before_any_client_exists() -> None:
    factory = FakeClientFactory(full_script())
    with pytest.raises(ConfigError):
        IamAdapter(profile="  ", region=REGION, client_factory=factory)
    assert factory.clients == {}


def test_missing_region_is_rejected_before_any_client_exists() -> None:
    factory = FakeClientFactory(full_script())
    with pytest.raises(ConfigError):
        IamAdapter(profile=PROFILE, region="", client_factory=factory)
    assert factory.clients == {}


def test_from_config_requires_the_explicit_opt_in_triple() -> None:
    config = RealityConfig(aws_opt_in=False, aws_profile=PROFILE, aws_region=REGION)
    with pytest.raises(ConfigError):
        IamAdapter.from_config(config)


def test_from_config_builds_an_adapter_from_a_valid_config() -> None:
    config = RealityConfig(aws_opt_in=True, aws_profile=PROFILE, aws_region=REGION)
    adapter = IamAdapter.from_config(config, client_factory=FakeClientFactory(full_script()))
    assert adapter.name == "iam"
    result = adapter.collect()
    assert result.resources  # the injected factory means no boto3 is needed


# --- safety: allowed operations only -------------------------------------------


def test_every_invoked_operation_is_in_the_read_only_whitelist() -> None:
    adapter, factory = make_adapter()
    adapter.collect()
    invoked = {op for client in factory.clients.values() for op, _ in client.calls}
    assert invoked <= ALLOWED_OPERATIONS
    assert invoked == ALLOWED_OPERATIONS  # a full scan uses every allowed operation


def test_whitelist_contains_only_list_and_get_operations() -> None:
    assert {
        "list_roles",
        "list_role_policies",
        "get_role_policy",
        "list_attached_role_policies",
        "get_policy",
        "get_policy_version",
    } == ALLOWED_OPERATIONS
    for operation in ALLOWED_OPERATIONS:
        assert operation.startswith(("list_", "get_"))


MUTATING_PREFIXES = (
    "create_",
    "delete_",
    "put_",
    "update_",
    "modify_",
    "terminate_",
    "attach_",
    "detach_",
    "authorize_",
    "revoke_",
    "run_",
    "start_",
    "stop_",
    "add_",
    "remove_",
    "set_",
    "register_",
    "enable_",
    "upload_",
    "tag_",
    "untag_",
    "simulate_",
)


def test_adapter_source_never_calls_mutating_operations() -> None:
    from reality.adapters import iam as module

    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = node.func
            name = getattr(called, "attr", None) or getattr(called, "id", None)
            assert name is None or not name.startswith(MUTATING_PREFIXES), (
                f"adapter must not call {name!r}"
            )


def test_boto3_is_imported_lazily_not_at_module_level() -> None:
    from reality.adapters import iam as module

    tree = ast.parse(inspect.getsource(module))
    boto_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Import) and any(alias.name == "boto3" for alias in node.names)
    ]
    assert boto_imports, "the default client factory must import boto3 somewhere"
    assert all(node.col_offset > 0 for node in boto_imports)  # nested in a function body


# --- discovery and canonicalization ---------------------------------------------


def test_roles_discovered_with_global_canonical_ids() -> None:
    result = collect_full()
    assert {r.canonical_id for r in result.resources} == {
        PROCESSOR_ROLE,
        CLEANUP_ROLE,
        AUDITOR_ROLE,
    }
    processor = next(r for r in result.resources if r.native_id == "processor_role")
    assert processor.resource_type == ResourceType.IAM_ROLE
    assert processor.provider == "aws"
    assert processor.region is None  # IAM is global
    assert processor.account == "123456789012"
    assert processor.arn == "arn:aws:iam::123456789012:role/processor_role"
    assert processor.name == "processor_role"
    assert processor.source == EvidenceSource.IAM


def test_role_with_malformed_arn_falls_back_to_native_identity() -> None:
    script = full_script()
    script["iam"]["list_roles"] = [
        {"Roles": [{"RoleName": "weird_role", "Arn": "not:an:arn"}], "IsTruncated": False}
    ]
    script["iam"]["list_role_policies"] = [{"PolicyNames": [], "IsTruncated": False}]
    script["iam"]["get_role_policy"] = []
    script["iam"]["list_attached_role_policies"] = [{"AttachedPolicies": [], "IsTruncated": False}]
    script["iam"]["get_policy"] = []
    script["iam"]["get_policy_version"] = []
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    assert [r.canonical_id for r in result.resources] == ["aws/iam/role/-/-/weird_role"]


def test_available_coverage_records_the_scan_context() -> None:
    result = collect_full()
    available = next(
        record for record in result.coverage if record.status == CoverageStatus.AVAILABLE
    )
    assert available.source == EvidenceSource.IAM
    assert available.region == REGION
    assert "3 role(s)" in available.reason
    assert PROFILE in available.reason
    assert REGION in available.reason
    assert "global" in available.reason


def test_full_scan_counts_are_exact() -> None:
    result = collect_full()
    assert len(result.resources) == 3
    assert len(result.relationships) == 8
    assert len(result.evidence) == 12
    assert len(result.coverage) == 2  # available summary + one malformed-policy record


# --- pagination ------------------------------------------------------------------


def test_list_roles_paginates_with_marker() -> None:
    adapter, factory = make_adapter()
    result = adapter.collect()
    assert {r.native_id for r in result.resources} == {
        "processor_role",
        "cleanup_role",
        "auditor_role",
    }
    assert calls_for(factory, "list_roles") == [{}, {"Marker": "roles-page-2"}]


def test_list_role_policies_paginates_with_marker() -> None:
    adapter, factory = make_adapter()
    adapter.collect()
    assert calls_for(factory, "list_role_policies") == [
        {"RoleName": "processor_role"},
        {"RoleName": "processor_role", "Marker": "pp-page-2"},
        {"RoleName": "cleanup_role"},
        {"RoleName": "auditor_role"},
    ]


# --- defensive parsing forms ------------------------------------------------------


def test_statement_as_single_object_is_parsed() -> None:
    result = collect_full()
    # cleanup-inline writes Statement as an object with scalar Action/Resource
    assert (CLEANUP_ROLE, CLEANUP_TASKS) in relationships_as_tuples(result)


def test_action_and_resource_lists_emit_one_evidence_per_pair() -> None:
    result = collect_full()
    inline = [item for item in result.evidence if f":{PROCESSOR_INLINE}:" in item.id]
    # 4 allow pairs (2 actions x 2 resources) + 1 deny pair
    assert len(inline) == 5
    allows_on_bucket = [
        item
        for item in inline
        if ":Allow:" in item.id and item.target_ref == "arn:aws:s3:::data-lake"
    ]
    assert len(allows_on_bucket) == 2  # one per action


def test_duplicate_resource_entries_are_deduplicated() -> None:
    result = collect_full()
    evidence_by_id = {item.id: item for item in result.evidence}
    assert len(evidence_by_id) == len(result.evidence)  # IDs are unique
    duplicated = [
        item
        for item in result.evidence
        if item.id.endswith(":Allow:s3:ListBucket:arn:aws:s3:::audit-logs")
    ]
    assert len(duplicated) == 1  # the repeated Resource entry collapsed to one


def test_policy_document_as_json_string_is_parsed() -> None:
    result = collect_full()
    # AuditorAccess's default version carries Document as a JSON string
    assert (AUDITOR_ROLE, AUDIT_QUEUE) in relationships_as_tuples(result)


def test_non_object_policy_document_becomes_unavailable_coverage() -> None:
    script = full_script()
    script["iam"]["get_role_policy"][0] = {
        "RoleName": "processor_role",
        "PolicyName": "processor-inline",
        "PolicyDocument": 42,
    }
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    record = next(
        record
        for record in result.coverage
        if "processor-inline" in record.reason and record.status == CoverageStatus.UNAVAILABLE
    )
    assert "parsed as a policy document" in record.reason
    # nothing was invented for the unusable policy
    assert not [item for item in result.evidence if f":{PROCESSOR_INLINE}:" in item.id]


# --- explicit deny handling ---------------------------------------------------------


def test_explicit_deny_is_evidence_but_never_a_relationship() -> None:
    result = collect_full()
    deny = next(item for item in result.evidence if ":Deny:" in item.id)
    assert deny.target_ref == "arn:aws:s3:::data-lake/*"
    assert "explicitly denies" in deny.explanation
    assert "never emitted as a permission candidate" in deny.explanation
    # no relationship anywhere is backed by the deny evidence
    for rel in result.relationships:
        assert deny.id not in rel.evidence_ids
    # the wildcard target has exactly one candidate: the allow, not the deny
    deny_target_rels = [
        rel for rel in result.relationships if rel.target_canonical_id == DATA_LAKE_WILDCARD
    ]
    assert len(deny_target_rels) == 1
    assert ":Allow:" in deny_target_rels[0].evidence_ids[0]


def test_allow_explanations_state_possible_not_proof() -> None:
    result = collect_full()
    allows = [item for item in result.evidence if ":Allow:" in item.id]
    assert allows
    for item in allows:
        assert "a POSSIBLE permission candidate, never proof of runtime use" in item.explanation


# --- wildcard and variable safety ----------------------------------------------------


def test_wildcard_resource_lands_in_unresolved_namespace_with_low_strength() -> None:
    result = collect_full()
    rels = relationships_as_tuples(result)
    assert (PROCESSOR_ROLE, DATA_LAKE_WILDCARD) in rels
    assert (PROCESSOR_ROLE, STAR) in rels
    for item in result.evidence:
        if item.target_ref in ("arn:aws:s3:::data-lake/*", "*"):
            assert item.strength == EvidenceStrength.LOW
            assert item.target_canonical_id.startswith("unresolved/")
            assert "pattern" in item.explanation


def test_policy_variable_resource_is_unknown_strength() -> None:
    result = collect_full()
    assert (PROCESSOR_ROLE, HOME_VARIABLE) in relationships_as_tuples(result)
    item = next(
        item for item in result.evidence if item.target_ref == "arn:aws:s3:::home/${aws:username}/*"
    )
    assert item.strength == EvidenceStrength.UNKNOWN
    assert "variables" in item.explanation
    assert "runtime context" in item.explanation


def test_non_arn_resource_string_is_recorded_unresolved() -> None:
    script = full_script()
    script["iam"]["get_role_policy"][1] = {
        "RoleName": "processor_role",
        "PolicyName": "processor-readonly",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ssm:GetParameter",
                    "Resource": "my-on-prem-hostname",
                }
            ],
        },
    }
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    rel = next(
        rel
        for rel in result.relationships
        if rel.target_canonical_id.endswith("my-on-prem-hostname")
    )
    assert rel.target_canonical_id == "unresolved/-/-/-/-/my-on-prem-hostname"
    evidence = next(item for item in result.evidence if item.id in rel.evidence_ids)
    assert evidence.strength == EvidenceStrength.LOW
    assert "not a normalizable ARN" in evidence.explanation


# --- attached managed-policy version selection ------------------------------------------


def test_default_managed_policy_version_is_selected() -> None:
    adapter, factory = make_adapter()
    adapter.collect()
    # DataReader's default is v2 (not v1); AuditorAccess has only v1
    assert calls_for(factory, "get_policy") == [
        {"PolicyArn": DATA_READER_ARN},
        {"PolicyArn": AUDITOR_ACCESS_ARN},
    ]
    assert calls_for(factory, "get_policy_version") == [
        {"PolicyArn": DATA_READER_ARN, "VersionId": "v2"},
        {"PolicyArn": AUDITOR_ACCESS_ARN, "VersionId": "v1"},
    ]


def test_attached_policy_targets_are_attributed_to_the_role() -> None:
    result = collect_full()
    # DataReader (managed) and processor-inline (inline) both grant as the role
    assert (PROCESSOR_ROLE, PROCESSED_EVENTS) in relationships_as_tuples(result)


# --- evidence shape ----------------------------------------------------------------------


def test_specific_resource_arns_normalize_to_canonical_targets() -> None:
    result = collect_full()
    resolved = {
        rel.target_canonical_id
        for rel in result.relationships
        if not rel.target_canonical_id.startswith("unresolved/")
    }
    assert resolved == {DATA_LAKE, AUDIT_LOGS, PROCESSED_EVENTS, CLEANUP_TASKS, AUDIT_QUEUE}


def test_relationships_are_permission_candidates_from_iam_policies() -> None:
    result = collect_full()
    evidence_by_id = {item.id: item for item in result.evidence}
    assert result.relationships
    for rel in result.relationships:
        assert rel.type == RelationshipType.PERMISSION_ON
        assert rel.origin == RelationshipOrigin.IAM_POLICY
        assert rel.evidence_ids
        for evidence_id in rel.evidence_ids:
            evidence = evidence_by_id[evidence_id]
            assert evidence.source == EvidenceSource.IAM
            assert evidence.type == EvidenceType.POLICY_STATEMENT
            assert evidence.observed_at is not None
            assert evidence.explanation
            assert evidence.source_canonical_id == rel.source_canonical_id
            assert evidence.target_canonical_id == rel.target_canonical_id


def test_evidence_raw_locators_point_at_the_policy() -> None:
    result = collect_full()
    inline = next(
        item
        for item in result.evidence
        if item.id.endswith(":Allow:s3:GetObject:arn:aws:s3:::data-lake")
    )
    assert inline.raw_locator == "iam:GetRolePolicy#processor_role/processor-inline.Statement[0]"
    managed = next(
        item
        for item in result.evidence
        if item.id.endswith(
            ":Allow:dynamodb:GetItem:arn:aws:dynamodb:eu-west-1:123456789012:table/processed-events"
        )
    )
    assert managed.raw_locator == f"iam:GetPolicyVersion#{DATA_READER}.Statement[0]"


def test_actor_is_the_declaring_policy() -> None:
    result = collect_full()
    inline = next(item for item in result.evidence if item.source_ref == PROCESSOR_INLINE)
    assert inline.actor == PROCESSOR_INLINE
    managed = next(item for item in result.evidence if item.source_ref == DATA_READER)
    assert managed.actor == DATA_READER


def test_evidence_ids_are_deterministic() -> None:
    first = collect_full()
    second = collect_full()
    assert {item.id for item in first.evidence} == {item.id for item in second.evidence}


# --- malformed policies and failure coverage ------------------------------------------------


def test_malformed_statements_are_counted_in_coverage_never_invented() -> None:
    result = collect_full()
    record = next(
        record for record in result.coverage if "malformed statement(s) skipped" in record.reason
    )
    assert record.status == CoverageStatus.UNAVAILABLE
    assert "4 malformed statement(s)" in record.reason
    assert "auditor-inline" in record.reason
    # the one usable statement in the same policy still produced its candidate
    assert (AUDITOR_ROLE, AUDIT_LOGS) in relationships_as_tuples(result)


def test_list_roles_access_denied_degrades_to_unavailable_coverage() -> None:
    script = full_script()
    script["iam"]["list_roles"] = [FakeClientError("AccessDenied")]
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    assert len(result.coverage) == 1
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "ListRoles" in result.coverage[0].reason
    assert "AccessDenied" in result.coverage[0].reason
    assert result.resources == ()
    assert result.relationships == ()
    assert result.evidence == ()


def test_access_denied_inline_policy_is_recorded_and_scan_continues() -> None:
    script = full_script()
    script["iam"]["get_role_policy"][0] = FakeClientError("AccessDenied")
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    record = next(
        record
        for record in result.coverage
        if "processor-inline" in record.reason and record.status == CoverageStatus.UNAVAILABLE
    )
    assert "AccessDenied" in record.reason
    # the role itself and every other policy are still reported
    ids = {r.canonical_id for r in result.resources}
    assert PROCESSOR_ROLE in ids
    assert (PROCESSOR_ROLE, PROCESSED_EVENTS) in relationships_as_tuples(result)


def test_access_denied_managed_policy_metadata_is_recorded() -> None:
    script = full_script()
    script["iam"]["get_policy"][0] = FakeClientError("AccessDenied")
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    record = next(
        record
        for record in result.coverage
        if DATA_READER_ARN in record.reason and record.status == CoverageStatus.UNAVAILABLE
    )
    assert "AccessDenied" in record.reason
    # nothing from DataReader was invented
    assert (PROCESSOR_ROLE, PROCESSED_EVENTS) not in relationships_as_tuples(result)
    # the inline policies of the same role are untouched
    assert (PROCESSOR_ROLE, DATA_LAKE) in relationships_as_tuples(result)


def test_throttled_policy_version_is_recorded_and_scan_continues() -> None:
    script = full_script()
    script["iam"]["get_policy_version"][0] = FakeClientError("Throttling")
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    record = next(
        record
        for record in result.coverage
        if "default version v2" in record.reason and record.status == CoverageStatus.UNAVAILABLE
    )
    assert "Throttling" in record.reason
    assert (PROCESSOR_ROLE, DATA_LAKE) in relationships_as_tuples(result)


def test_unexpected_client_error_code_propagates() -> None:
    script = full_script()
    script["iam"]["get_policy"] = [FakeClientError("InvalidParameterException")]
    adapter, _ = make_adapter(script)
    with pytest.raises(FakeClientError):
        adapter.collect()


def test_non_client_error_propagates() -> None:
    script = full_script()
    script["iam"]["list_roles"] = [ValueError("boom")]
    adapter, _ = make_adapter(script)
    with pytest.raises(ValueError, match="boom"):
        adapter.collect()


# --- optional: real botocore Stubber, only when the aws extra is installed --------------------


class TestWithBotocoreStubber:
    def test_real_client_error_shape_is_classified(self) -> None:
        boto3 = pytest.importorskip("boto3")
        pytest.importorskip("botocore")
        from botocore.stub import Stubber

        client = boto3.client(
            "iam",
            region_name=REGION,
            aws_access_key_id="AKIAFAKEFAKEFAKEFAKE",  # never used: all calls are stubbed
            aws_secret_access_key="fixture-only-not-a-secret",
        )
        stubber = Stubber(client)
        # list_roles is the first and only call: its failure ends the scan.
        stubber.add_client_error("list_roles", service_error_code="AccessDenied")
        stubber.activate()

        class SingleClientFactory:
            def __call__(self, service: str) -> Any:
                assert service == "iam"
                return client

        adapter = IamAdapter(profile=PROFILE, region=REGION, client_factory=SingleClientFactory())
        result = adapter.collect()
        assert len(result.coverage) == 1
        assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
        assert "AccessDenied" in result.coverage[0].reason
