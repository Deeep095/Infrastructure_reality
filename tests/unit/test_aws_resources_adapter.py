"""Tests for the read-only AWS resource adapter.

Everything runs against fake injected clients (plus, when the optional aws
extra is installed, one botocore Stubber case). No test needs credentials, a
profile, or network access, and none can mutate anything: the fake client
refuses every operation outside the read-only whitelist.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from reality.adapters.aws_resources import ALLOWED_OPERATIONS, AwsResourcesAdapter
from reality.adapters.base import AdapterError
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

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "aws"

PROFILE = "sandbox"
REGION = "eu-west-1"
ACCOUNT = "123456789012"
PRINCIPAL = "arn:aws:iam::123456789012:user/reality-scan"

WEB = "aws/ec2/instance/eu-west-1/123456789012/i-0web"
BATCH = "aws/ec2/instance/eu-west-1/123456789012/i-0batch"
WEB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0aaa111"
DB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0bbb222"
UNDECLARED_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0zzz999"
PROCESSOR = "aws/lambda/function/eu-west-1/123456789012/processor"
CLEANUP = "aws/lambda/function/eu-west-1/123456789012/cleanup"
PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
CLEANUP_ROLE = "aws/iam/role/-/123456789012/cleanup_role"
PRIMARY_DB = "aws/rds/db/eu-west-1/123456789012/primary"
REPORTING_DB = "aws/rds/db/eu-west-1/123456789012/reporting"
DATA_LAKE = "aws/s3/bucket/-/123456789012/data-lake"
STATIC_ASSETS = "aws/s3/bucket/-/123456789012/static-assets"


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
    return {
        "sts": {"get_caller_identity": [load("get_caller_identity.json")]},
        "ec2": {
            "describe_instances": list(load("describe_instances.json")["pages"]),
            "describe_security_groups": list(load("describe_security_groups.json")["pages"]),
        },
        "lambda": {"list_functions": list(load("list_functions.json")["pages"])},
        "rds": {"describe_db_instances": list(load("describe_db_instances.json")["pages"])},
        "s3": {"list_buckets": [load("list_buckets.json")]},
    }


def make_adapter(
    script: dict[str, dict[str, list[Any]]] | None = None,
) -> tuple[AwsResourcesAdapter, FakeClientFactory]:
    factory = FakeClientFactory(script if script is not None else full_script())
    adapter = AwsResourcesAdapter(profile=PROFILE, region=REGION, client_factory=factory)
    return adapter, factory


def collect_full() -> Any:
    adapter, _ = make_adapter()
    return adapter.collect()


# --- configuration gate -------------------------------------------------------


def test_blank_profile_is_rejected_before_any_client_exists() -> None:
    factory = FakeClientFactory(full_script())
    with pytest.raises(ConfigError):
        AwsResourcesAdapter(profile="  ", region=REGION, client_factory=factory)
    assert factory.clients == {}


def test_missing_region_is_rejected_before_any_client_exists() -> None:
    factory = FakeClientFactory(full_script())
    with pytest.raises(ConfigError):
        AwsResourcesAdapter(profile=PROFILE, region="", client_factory=factory)
    assert factory.clients == {}


def test_from_config_requires_the_explicit_opt_in_triple() -> None:
    config = RealityConfig(aws_opt_in=False, aws_profile=PROFILE, aws_region=REGION)
    with pytest.raises(ConfigError):
        AwsResourcesAdapter.from_config(config)


def test_from_config_builds_an_adapter_from_a_valid_config() -> None:
    config = RealityConfig(aws_opt_in=True, aws_profile=PROFILE, aws_region=REGION)
    adapter = AwsResourcesAdapter.from_config(
        config, client_factory=FakeClientFactory(full_script())
    )
    assert adapter.name == "aws_resources"
    result = adapter.collect()
    assert result.resources  # the injected factory means no boto3 is needed


# --- safety: allowed operations only -------------------------------------------


def test_every_invoked_operation_is_in_the_read_only_whitelist() -> None:
    adapter, factory = make_adapter()
    adapter.collect()
    invoked = {op for client in factory.clients.values() for op, _ in client.calls}
    assert invoked <= ALLOWED_OPERATIONS
    assert invoked == ALLOWED_OPERATIONS  # a full scan uses every allowed operation


def test_whitelist_contains_only_read_list_describe_operations() -> None:
    assert {
        "get_caller_identity",
        "describe_instances",
        "describe_security_groups",
        "list_functions",
        "describe_db_instances",
        "list_buckets",
    } == ALLOWED_OPERATIONS
    for operation in ALLOWED_OPERATIONS:
        assert operation.startswith(("get_", "list_", "describe_"))


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
)


def test_adapter_source_never_calls_mutating_operations() -> None:
    from reality.adapters import aws_resources as module

    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = node.func
            name = getattr(called, "attr", None) or getattr(called, "id", None)
            assert name is None or not name.startswith(MUTATING_PREFIXES), (
                f"adapter must not call {name!r}"
            )


def test_boto3_is_imported_lazily_not_at_module_level() -> None:
    from reality.adapters import aws_resources as module

    tree = ast.parse(inspect.getsource(module))
    boto_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Import) and any(alias.name == "boto3" for alias in node.names)
    ]
    assert boto_imports, "the default client factory must import boto3 somewhere"
    assert all(node.col_offset > 0 for node in boto_imports)  # nested in a function body


# --- discovery and canonicalization ---------------------------------------------


def test_ec2_instances_discovered_with_canonical_ids() -> None:
    result = collect_full()
    web = next(r for r in result.resources if r.native_id == "i-0web")
    assert web.canonical_id == WEB
    assert web.resource_type == ResourceType.EC2_INSTANCE
    assert web.provider == "aws"
    assert web.region == REGION
    assert web.account == ACCOUNT
    assert web.source == EvidenceSource.AWS_RESOURCES


def test_instance_name_comes_from_the_name_tag() -> None:
    result = collect_full()
    web = next(r for r in result.resources if r.native_id == "i-0web")
    assert web.name == "web-server"  # the Team tag is not stored


def test_security_groups_discovered_with_canonical_ids() -> None:
    result = collect_full()
    ids = {r.canonical_id for r in result.resources}
    assert WEB_SG in ids
    assert DB_SG in ids
    web_sg = next(r for r in result.resources if r.native_id == "sg-0aaa111")
    assert web_sg.resource_type == ResourceType.SECURITY_GROUP
    assert web_sg.name == "web-sg"


def test_lambda_functions_normalize_through_their_arn() -> None:
    result = collect_full()
    fn = next(r for r in result.resources if r.native_id == "processor")
    assert fn.canonical_id == PROCESSOR
    assert fn.arn == "arn:aws:lambda:eu-west-1:123456789012:function:processor"
    assert fn.region == REGION
    assert fn.account == ACCOUNT


def test_rds_instances_normalize_through_their_arn() -> None:
    result = collect_full()
    db = next(r for r in result.resources if r.native_id == "primary")
    assert db.canonical_id == PRIMARY_DB
    assert db.arn == "arn:aws:rds:eu-west-1:123456789012:db:primary"
    assert db.resource_type == ResourceType.RDS_DB_INSTANCE


def test_s3_buckets_are_global_with_no_inferred_region() -> None:
    result = collect_full()
    ids = {r.canonical_id for r in result.resources}
    assert ids >= {DATA_LAKE, STATIC_ASSETS}
    for bucket in (r for r in result.resources if r.resource_type == ResourceType.S3_BUCKET):
        assert bucket.region is None  # BucketRegion from the response is ignored
        assert bucket.arn is None  # no synthesized ARN
        assert bucket.account == ACCOUNT  # scan context, not an inferred region


# --- pagination ------------------------------------------------------------------


def test_ec2_instances_paginate_with_next_token() -> None:
    adapter, factory = make_adapter()
    result = adapter.collect()
    instances = {
        r.native_id for r in result.resources if r.resource_type == ResourceType.EC2_INSTANCE
    }
    assert instances == {"i-0web", "i-0batch"}
    calls = [kw for op, kw in factory.clients["ec2"].calls if op == "describe_instances"]
    assert calls == [{}, {"NextToken": "inst-page-2"}]


def test_security_groups_paginate_with_next_token() -> None:
    adapter, factory = make_adapter()
    adapter.collect()
    calls = [kw for op, kw in factory.clients["ec2"].calls if op == "describe_security_groups"]
    assert calls == [{}, {"NextToken": "sg-page-2"}]


def test_lambda_functions_paginate_with_marker() -> None:
    adapter, factory = make_adapter()
    result = adapter.collect()
    functions = {
        r.native_id for r in result.resources if r.resource_type == ResourceType.LAMBDA_FUNCTION
    }
    assert functions == {"processor", "cleanup"}
    calls = [kw for op, kw in factory.clients["lambda"].calls if op == "list_functions"]
    assert calls == [{}, {"Marker": "fn-page-2"}]


def test_rds_instances_paginate_with_marker() -> None:
    adapter, factory = make_adapter()
    result = adapter.collect()
    databases = {
        r.native_id for r in result.resources if r.resource_type == ResourceType.RDS_DB_INSTANCE
    }
    assert databases == {"primary", "reporting"}
    calls = [kw for op, kw in factory.clients["rds"].calls if op == "describe_db_instances"]
    assert calls == [{}, {"Marker": "db-page-2"}]


# --- relationships and evidence -----------------------------------------------------


def relationships_as_tuples(result: Any) -> set[tuple[str, str, RelationshipType]]:
    return {
        (rel.source_canonical_id, rel.target_canonical_id, rel.type) for rel in result.relationships
    }


def test_instance_to_security_group_relationships() -> None:
    result = collect_full()
    rels = relationships_as_tuples(result)
    assert (WEB, WEB_SG, RelationshipType.ATTACHED_TO) in rels
    assert (WEB, UNDECLARED_SG, RelationshipType.ATTACHED_TO) in rels  # declared or not
    assert (BATCH, DB_SG, RelationshipType.ATTACHED_TO) in rels


def test_lambda_to_execution_role_relationship() -> None:
    result = collect_full()
    rels = relationships_as_tuples(result)
    assert (PROCESSOR, PROCESSOR_ROLE, RelationshipType.PERMISSION_ON) in rels
    assert (CLEANUP, CLEANUP_ROLE, RelationshipType.PERMISSION_ON) in rels


def test_rds_to_security_group_relationship() -> None:
    result = collect_full()
    rels = relationships_as_tuples(result)
    assert (PRIMARY_DB, WEB_SG, RelationshipType.ATTACHED_TO) in rels
    assert not any(rel.source_canonical_id == REPORTING_DB for rel in result.relationships)


def test_relationships_carry_observed_attribute_evidence() -> None:
    result = collect_full()
    evidence_by_id = {item.id: item for item in result.evidence}
    assert len(evidence_by_id) == len(result.evidence)  # IDs are unique
    assert result.relationships
    for rel in result.relationships:
        assert rel.origin == RelationshipOrigin.AWS_OBSERVED
        assert rel.evidence_ids
        for evidence_id in rel.evidence_ids:
            evidence = evidence_by_id[evidence_id]
            assert evidence.source == EvidenceSource.AWS_RESOURCES
            assert evidence.type == EvidenceType.OBSERVED_ATTRIBUTE
            assert evidence.strength == EvidenceStrength.HIGH  # AWS directly reports it
            assert evidence.actor == PRINCIPAL
            assert evidence.observed_at is not None
            assert evidence.explanation
            assert evidence.source_canonical_id == rel.source_canonical_id
            assert evidence.target_canonical_id == rel.target_canonical_id


def test_evidence_raw_locators_point_at_the_api_call() -> None:
    result = collect_full()
    locator = next(
        item.raw_locator
        for item in result.evidence
        if item.id.startswith("aws:ec2:DescribeInstances:")
        and item.id.endswith(":SecurityGroups:sg-0aaa111")
    )
    assert locator.startswith("ec2:DescribeInstances#Reservations[")
    assert ".SecurityGroups[" in locator


def test_evidence_ids_are_deterministic() -> None:
    first = collect_full()
    second = collect_full()
    assert {item.id for item in first.evidence} == {item.id for item in second.evidence}


# --- coverage -------------------------------------------------------------------------


def test_coverage_has_one_record_per_consulted_service() -> None:
    result = collect_full()
    assert len(result.coverage) == 6  # sts + five resource services
    assert all(record.source == EvidenceSource.AWS_RESOURCES for record in result.coverage)
    assert all(record.region == REGION for record in result.coverage)


def test_sts_identity_is_recorded_in_coverage() -> None:
    result = collect_full()
    identity = result.coverage[0]
    assert identity.status == CoverageStatus.AVAILABLE
    assert ACCOUNT in identity.reason
    assert PRINCIPAL in identity.reason
    assert PROFILE in identity.reason
    assert REGION in identity.reason


def test_s3_coverage_records_the_selected_scan_context() -> None:
    result = collect_full()
    s3 = next(record for record in result.coverage if "ListBuckets" in record.reason)
    assert s3.status == CoverageStatus.AVAILABLE
    assert s3.region == REGION  # the selected scan region, while buckets stay region-less
    assert PROFILE in s3.reason
    assert "global" in s3.reason


# --- failure isolation -------------------------------------------------------------------


def test_access_denied_service_degrades_to_unavailable_coverage() -> None:
    script = full_script()
    script["ec2"]["describe_instances"] = [FakeClientError("UnauthorizedOperation")]
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    ec2 = next(record for record in result.coverage if "DescribeInstances" in record.reason)
    assert ec2.status == CoverageStatus.UNAVAILABLE
    assert "UnauthorizedOperation" in ec2.reason
    # the scan continued: the other services are present
    ids = {r.canonical_id for r in result.resources}
    assert PROCESSOR in ids
    assert DATA_LAKE in ids
    # and no half-discovered instances survive
    assert not [r for r in result.resources if r.resource_type == ResourceType.EC2_INSTANCE]


def test_throttling_mid_pagination_discards_partial_results() -> None:
    script = full_script()
    pages = list(load("describe_instances.json")["pages"])
    script["ec2"]["describe_instances"] = [pages[0], FakeClientError("Throttling")]
    adapter, _ = make_adapter(script)
    result = adapter.collect()
    assert not [r for r in result.resources if r.resource_type == ResourceType.EC2_INSTANCE]
    ec2 = next(record for record in result.coverage if "DescribeInstances" in record.reason)
    assert ec2.status == CoverageStatus.UNAVAILABLE
    assert "Throttling" in ec2.reason


def test_unexpected_client_error_code_propagates() -> None:
    script = full_script()
    script["ec2"]["describe_instances"] = [FakeClientError("InvalidParameterException")]
    adapter, _ = make_adapter(script)
    with pytest.raises(FakeClientError):
        adapter.collect()


def test_non_client_error_propagates() -> None:
    script = full_script()
    script["lambda"]["list_functions"] = [ValueError("boom")]
    adapter, _ = make_adapter(script)
    with pytest.raises(ValueError, match="boom"):
        adapter.collect()


def test_sts_failure_is_fatal_to_the_scan() -> None:
    script = full_script()
    script["sts"]["get_caller_identity"] = [FakeClientError("AccessDenied")]
    adapter, _ = make_adapter(script)
    with pytest.raises(AdapterError) as exc_info:
        adapter.collect()
    assert "GetCallerIdentity" in str(exc_info.value)


# --- secrets never extracted ---------------------------------------------------------------


def test_secret_bearing_fields_are_never_extracted() -> None:
    result = collect_full()
    dump = json.dumps(result.model_dump(mode="json"))
    assert "sk-live-abc123-do-not-leak" not in dump  # lambda env var
    assert "super-seeker-password-fixture-only" not in dump  # rds credential field
    assert "MasterUserPassword" not in dump
    assert "API_KEY" not in dump


# --- optional: real botocore Stubber, only when the aws extra is installed --------------------


class TestWithBotocoreStubber:
    def test_real_client_error_shape_is_classified(self) -> None:
        boto3 = pytest.importorskip("boto3")
        pytest.importorskip("botocore")
        from botocore.stub import Stubber

        client = boto3.client(
            "ec2",
            region_name=REGION,
            aws_access_key_id="AKIAFAKEFAKEFAKEFAKE",  # never used: all calls are stubbed
            aws_secret_access_key="fixture-only-not-a-secret",
        )
        stubber = Stubber(client)
        # The adapter calls describe_instances first, then describe_security_groups
        # on the same client; Stubber's queue is strictly sequential, so both
        # must be scripted in call order.
        stubber.add_client_error("describe_instances", service_error_code="UnauthorizedOperation")
        stubber.add_response("describe_security_groups", {"SecurityGroups": []})
        stubber.activate()

        class MixedFactory:
            """Real stubbed ec2 client; fakes for everything else."""

            def __init__(self) -> None:
                self.clients: dict[str, Any] = {}

            def __call__(self, service: str) -> Any:
                return client if service == "ec2" else FakeClient(service, full_script()[service])

        adapter = AwsResourcesAdapter(profile=PROFILE, region=REGION, client_factory=MixedFactory())
        result = adapter.collect()
        ec2 = next(record for record in result.coverage if "DescribeInstances" in record.reason)
        assert ec2.status == CoverageStatus.UNAVAILABLE
        assert "UnauthorizedOperation" in ec2.reason
        ids = {r.canonical_id for r in result.resources}
        assert PROCESSOR in ids  # the scan continued past the real error shape
