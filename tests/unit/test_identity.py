"""Unit tests for evidence-backed identity mappings.

The join under test is the one place a ``terraform/…`` identity may become an
``aws/…`` identity: an exact ARN or native-ID match recorded as a mapping
with its own evidence. Every test builds the declared and observed resources
one scan would have collected and asserts which joins happened, which were
refused, and what evidence backs each one. No store, no adapters — the
computation is pure over the resource list.
"""

from __future__ import annotations

from reality.domain.enums import (
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    MappingBasis,
    ResourceType,
)
from reality.domain.models import Resource
from reality.services.identity import compute_identity_mappings

ACCOUNT = "123456789012"
REGION = "eu-west-1"

#: The declared world: Terraform state resources, identified by address.
TF_WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"
TF_WEB_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0web"

TF_BATCH = "terraform/aws/aws_instance/-/-/aws_instance.batch"  # no ARN in state
TF_BATCH_ID = "i-0batch"  # its native ID

TF_PROCESSOR = "terraform/aws/aws_lambda_function/-/-/aws_lambda_function.processor"
TF_PROCESSOR_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:processor"

TF_CDN = "terraform/aws/aws_cloudfront_distribution/-/-/aws_cloudfront_distribution.cdn"
TF_CDN_ARN = "arn:aws:cloudfront::123456789012:distribution/EFUXMPEXAMPLE"

#: The observed world: AWS resources, identified by canonical key.
WEB = f"aws/ec2/instance/{REGION}/{ACCOUNT}/i-0web"
BATCH = f"aws/ec2/instance/{REGION}/{ACCOUNT}/i-0batch"
PROCESSOR = f"aws/lambda/function/{REGION}/{ACCOUNT}/processor"
CDN = "aws/cloudfront/distribution/-/123456789012/EFUXMPEXAMPLE"


def tf_resource(
    canonical_id: str,
    *,
    resource_type: ResourceType = ResourceType.TERRAFORM_RESOURCE,
    arn: str | None = None,
    native_id: str | None = None,
    address: str | None = None,
    name: str | None = None,
) -> Resource:
    return Resource(
        canonical_id=canonical_id,
        resource_type=resource_type,
        provider="terraform",
        native_id=native_id,
        arn=arn,
        terraform_address=address,
        name=name,
        source=EvidenceSource.TERRAFORM_STATE,
    )


def aws_resource(
    canonical_id: str,
    *,
    resource_type: ResourceType,
    arn: str | None = None,
    native_id: str | None = None,
    name: str | None = None,
) -> Resource:
    provider, service, rtype, region, account, _ = canonical_id.split("/", 5)
    return Resource(
        canonical_id=canonical_id,
        resource_type=resource_type,
        provider=provider,
        native_id=native_id,
        arn=arn,
        region=None if region == "-" else region,
        account=None if account == "-" else account,
        name=name,
        source=EvidenceSource.AWS_RESOURCES,
    )


def joins(resources: list[Resource]) -> dict[str, str]:
    """terraform_id -> aws_id for every computed mapping."""
    return {
        computed.mapping.terraform_canonical_id: computed.mapping.aws_canonical_id
        for computed in compute_identity_mappings(resources)
    }


# --- exact ARN joins ---------------------------------------------------------------


def test_arn_match_joins() -> None:
    resources = [
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            native_id="i-0other",  # deliberately unlike the observed native ID
            address="aws_instance.web",
        ),
        aws_resource(WEB, resource_type=ResourceType.EC2_INSTANCE, native_id="i-0web"),
    ]
    assert joins(resources) == {TF_WEB: WEB}


def test_arn_join_of_a_global_service_needs_no_region() -> None:
    # A CloudFront ARN has no region; the discovered distribution has none
    # either — global services join on the account alone.
    resources = [
        tf_resource(
            TF_CDN,
            resource_type=ResourceType.EXTERNAL,
            arn=TF_CDN_ARN,
            address="aws_cloudfront_distribution.cdn",
        ),
        aws_resource(CDN, resource_type=ResourceType.EXTERNAL, native_id="EFUXMPEXAMPLE"),
    ]
    assert joins(resources) == {TF_CDN: CDN}


def test_arn_across_region_never_joins() -> None:
    # The state declares an instance in eu-west-1; an instance with the SAME
    # ID exists in eu-central-1. Region is part of identity: no join.
    resources = [
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            address="aws_instance.web",
        ),
        aws_resource(
            f"aws/ec2/instance/eu-central-1/{ACCOUNT}/i-0web",
            resource_type=ResourceType.EC2_INSTANCE,
            native_id="i-0web",
        ),
    ]
    assert joins(resources) == {}


def test_parseable_but_unmatched_arn_blocks_the_native_fallback() -> None:
    # The state's ARN names i-0web, which nothing observed matches — while
    # the native ID points at an observed i-0batch. The ARN is authoritative:
    # falling back to the native ID would silently join a contradiction, so
    # nothing joins.
    resources = [
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            native_id=TF_BATCH_ID,
            address="aws_instance.web",
        ),
        aws_resource(BATCH, resource_type=ResourceType.EC2_INSTANCE, native_id=TF_BATCH_ID),
    ]
    assert joins(resources) == {}


# --- native-ID fallback --------------------------------------------------------------


def test_native_id_match_joins_without_an_arn() -> None:
    resources = [
        tf_resource(
            TF_BATCH,
            resource_type=ResourceType.EC2_INSTANCE,
            native_id=TF_BATCH_ID,
            address="aws_instance.batch",
        ),
        aws_resource(BATCH, resource_type=ResourceType.EC2_INSTANCE, native_id=TF_BATCH_ID),
    ]
    assert joins(resources) == {TF_BATCH: BATCH}


def test_native_id_requires_the_same_resource_type() -> None:
    # A security group and an instance can share a name-like native ID by
    # construction of the test; different types never join.
    resources = [
        tf_resource(
            TF_BATCH,
            resource_type=ResourceType.EC2_INSTANCE,
            native_id="i-0batch",
            address="aws_instance.batch",
        ),
        aws_resource(
            f"aws/ec2/security-group/{REGION}/{ACCOUNT}/i-0batch",
            resource_type=ResourceType.SECURITY_GROUP,
            native_id="i-0batch",
        ),
    ]
    assert joins(resources) == {}


def test_ambiguous_native_id_maps_nothing() -> None:
    # Two observed instances share the native ID: exactly-one-match fails.
    resources = [
        tf_resource(
            TF_BATCH,
            resource_type=ResourceType.EC2_INSTANCE,
            native_id=TF_BATCH_ID,
            address="aws_instance.batch",
        ),
        aws_resource(BATCH, resource_type=ResourceType.EC2_INSTANCE, native_id=TF_BATCH_ID),
        aws_resource(
            f"aws/ec2/instance/{REGION}/{ACCOUNT}/i-0batch-mirror",
            resource_type=ResourceType.EC2_INSTANCE,
            native_id=TF_BATCH_ID,
        ),
    ]
    assert joins(resources) == {}


def test_unparseable_arn_falls_back_to_the_native_id() -> None:
    # A malformed ARN proves nothing; the native ID may still join.
    resources = [
        tf_resource(
            TF_BATCH,
            resource_type=ResourceType.EC2_INSTANCE,
            arn="not-an-arn:i-0batch",
            native_id=TF_BATCH_ID,
            address="aws_instance.batch",
        ),
        aws_resource(BATCH, resource_type=ResourceType.EC2_INSTANCE, native_id=TF_BATCH_ID),
    ]
    assert joins(resources) == {TF_BATCH: BATCH}


# --- names never join ------------------------------------------------------------------


def test_similar_names_never_join() -> None:
    # The declared "web" and observed "web-server" would fuzzy-match by name;
    # identity never reads the name field. No ARN, and the native IDs differ,
    # so no exact identifier joins the two.
    resources = [
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            native_id="i-0declared",
            address="aws_instance.web",
            name="web",
        ),
        aws_resource(
            WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            native_id="i-0web",
            name="web-server",
        ),
    ]
    assert joins(resources) == {}


# --- ambiguity and exclusion guards ------------------------------------------------------


def test_two_declarations_claiming_one_observed_resource_map_nothing() -> None:
    # Two state resources carry the same ARN (a copy-paste in the fixture):
    # the state disagrees with itself, so neither joins.
    resources = [
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            address="aws_instance.web",
        ),
        tf_resource(
            "terraform/aws/aws_instance/-/-/aws_instance.web_copy",
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            address="aws_instance.web_copy",
        ),
        aws_resource(WEB, resource_type=ResourceType.EC2_INSTANCE, native_id="i-0web"),
    ]
    assert joins(resources) == {}


def test_plan_declarations_never_join() -> None:
    # planned_values describe the future; a resource whose source is the plan
    # carries no identity join even when its ARN matches an observed resource.
    planned = Resource(
        canonical_id=TF_PROCESSOR,
        resource_type=ResourceType.LAMBDA_FUNCTION,
        provider="terraform",
        arn=TF_PROCESSOR_ARN,
        terraform_address="aws_lambda_function.processor",
        source=EvidenceSource.TERRAFORM_PLAN,
    )
    observed = aws_resource(
        PROCESSOR,
        resource_type=ResourceType.LAMBDA_FUNCTION,
        arn=TF_PROCESSOR_ARN,
        native_id="processor",
    )
    assert compute_identity_mappings([planned, observed]) == ()


def test_only_terraform_and_aws_partitions_participate() -> None:
    # Unresolved resources are never join candidates on either side.
    resources = [
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            address="aws_instance.web",
        ),
        Resource(
            canonical_id="unresolved/-/-/-/-/arn:aws:ec2:*",
            resource_type=ResourceType.EXTERNAL,
            provider="unresolved",
        ),
    ]
    assert joins(resources) == {}


# --- the evidence and reason behind each join ---------------------------------------------


def test_each_mapping_carries_evidence_and_reason() -> None:
    resources = [
        tf_resource(
            TF_PROCESSOR,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            arn=TF_PROCESSOR_ARN,
            address="aws_lambda_function.processor",
        ),
        aws_resource(
            PROCESSOR,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            arn=TF_PROCESSOR_ARN,
            native_id="processor",
        ),
    ]
    computed = compute_identity_mappings(resources)

    assert len(computed) == 1
    mapping, evidence = computed[0].mapping, computed[0].evidence
    assert mapping.basis is MappingBasis.ARN
    assert mapping.matched_value == TF_PROCESSOR_ARN
    assert mapping.evidence_id == f"identity:{TF_PROCESSOR}:{PROCESSOR}"

    assert evidence.id == mapping.evidence_id  # the mapping points at this record
    assert evidence.source is EvidenceSource.TERRAFORM_STATE
    assert evidence.type is EvidenceType.IDENTITY_MATCH
    assert evidence.strength is EvidenceStrength.HIGH
    assert evidence.source_ref == "aws_lambda_function.processor"
    assert evidence.target_ref == PROCESSOR
    assert evidence.source_canonical_id == TF_PROCESSOR
    assert evidence.target_canonical_id == PROCESSOR
    assert evidence.raw_locator == ("terraform_state#aws_lambda_function.processor.values.arn")
    assert TF_PROCESSOR_ARN in evidence.explanation  # the exact identifier, not a name
    assert "never a name match" in mapping.reason


def test_native_join_records_the_native_basis() -> None:
    resources = [
        tf_resource(
            TF_BATCH,
            resource_type=ResourceType.EC2_INSTANCE,
            native_id=TF_BATCH_ID,
            address="aws_instance.batch",
        ),
        aws_resource(BATCH, resource_type=ResourceType.EC2_INSTANCE, native_id=TF_BATCH_ID),
    ]
    computed = compute_identity_mappings(resources)
    assert computed[0].mapping.basis is MappingBasis.NATIVE_ID
    assert computed[0].mapping.matched_value == TF_BATCH_ID
    assert computed[0].evidence.raw_locator == "terraform_state#aws_instance.batch.values.id"


def test_result_is_deterministic() -> None:
    resources = [
        tf_resource(
            TF_PROCESSOR,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            arn=TF_PROCESSOR_ARN,
            address="aws_lambda_function.processor",
        ),
        tf_resource(
            TF_WEB,
            resource_type=ResourceType.EC2_INSTANCE,
            arn=TF_WEB_ARN,
            address="aws_instance.web",
        ),
        aws_resource(
            PROCESSOR,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            arn=TF_PROCESSOR_ARN,
            native_id="processor",
        ),
        aws_resource(WEB, resource_type=ResourceType.EC2_INSTANCE, native_id="i-0web"),
    ]
    first = compute_identity_mappings(resources)
    second = compute_identity_mappings(list(reversed(resources)))
    assert first == second
    # Ordered by the Terraform canonical ID, regardless of input order.
    assert [c.mapping.terraform_canonical_id for c in first] == [TF_WEB, TF_PROCESSOR]
