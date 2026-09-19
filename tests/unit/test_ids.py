"""Fixture-driven tests for canonical-ID normalization and join safety."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reality.domain.ids import (
    CanonicalId,
    IdParseError,
    canonical_from_native,
    parse_arn,
    parse_canonical,
    parse_terraform_address,
    refine,
    safe_join,
    unresolved,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ids" / "cases.json"


def _cases() -> dict[str, list]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


# --- ARN parsing ------------------------------------------------------------


@pytest.mark.parametrize("case", _cases()["arns"])
def test_arn_parses_to_expected_key(case: dict) -> None:
    cid = parse_arn(case["arn"])
    assert cid.key == case["key"]
    assert str(cid) == case["key"]


def test_arn_preserves_native_identity_fields() -> None:
    cid = parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456")
    assert cid.provider == "aws"
    assert cid.service == "ec2"
    assert cid.resource_type == "instance"
    assert cid.resource_id == "i-0abc123def456"
    assert cid.region == "eu-west-1"
    assert cid.account == "123456789012"


def test_global_services_are_regionless() -> None:
    # S3 is global: even an ARN claiming a region normalizes to region None.
    cid = parse_arn("arn:aws:s3:eu-west-1:::acme-customer-data")
    assert cid.is_global
    assert cid.region is None
    assert cid.key == "aws/s3/bucket/-/-/acme-customer-data"


def test_region_scoped_services_are_not_global() -> None:
    assert parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-1").is_global is False


@pytest.mark.parametrize("arn", _cases()["malformed_arns"])
def test_malformed_arns_are_rejected(arn: str) -> None:
    with pytest.raises(IdParseError):
        parse_arn(arn)


def test_wildcard_arn_error_points_at_unresolved() -> None:
    with pytest.raises(IdParseError, match="unresolved"):
        parse_arn("arn:aws:s3:::acme-customer-*")


# --- Terraform addresses ----------------------------------------------------


@pytest.mark.parametrize("case", _cases()["terraform_addresses"])
def test_terraform_address_parses_to_expected_key(case: dict) -> None:
    cid = parse_terraform_address(case["address"])
    assert cid.key == case["key"]
    assert cid.resource_id == case["address"]  # original address preserved


@pytest.mark.parametrize("address", _cases()["malformed_terraform_addresses"])
def test_malformed_terraform_addresses_are_rejected(address: str) -> None:
    with pytest.raises(IdParseError):
        parse_terraform_address(address)


def test_terraform_address_extracts_service_from_type() -> None:
    cid = parse_terraform_address("module.vpc.aws_instance.web[0]")
    assert cid.provider == "terraform"
    assert cid.service == "aws"
    assert cid.resource_type == "aws_instance"
    assert cid.is_unresolved is False


# --- Native IDs -------------------------------------------------------------


@pytest.mark.parametrize("case", _cases()["native"])
def test_native_id_builds_expected_key(case: dict) -> None:
    cid = canonical_from_native(
        case["service"],
        case["resource_type"],
        case["resource_id"],
        region=case["region"],
        account=case["account"],
    )
    assert cid.key == case["key"]


def test_region_scoped_native_id_requires_region() -> None:
    with pytest.raises(IdParseError, match="region"):
        canonical_from_native("ec2", "instance", "i-0abc123def456")


def test_global_native_id_ignores_region() -> None:
    cid = canonical_from_native("s3", "bucket", "acme-customer-data", region="eu-west-1")
    assert cid.region is None
    assert cid.key == "aws/s3/bucket/-/-/acme-customer-data"


def test_wildcard_native_id_is_rejected() -> None:
    with pytest.raises(IdParseError, match="wildcard"):
        canonical_from_native("s3", "bucket", "acme-*", region=None)


# --- Unresolved external targets -------------------------------------------


@pytest.mark.parametrize("reference", _cases()["unresolved_references"])
def test_unresolved_targets_never_join(reference: str) -> None:
    target = unresolved(reference)
    assert target.is_unresolved
    assert target.resource_id == reference  # raw reference preserved
    resolved = parse_arn("arn:aws:s3:::acme-customer-data")
    assert safe_join(target, resolved) is False
    assert safe_join(target, target) is False


def test_unresolved_rejects_empty_reference() -> None:
    with pytest.raises(IdParseError):
        unresolved("   ")


# --- Join safety ------------------------------------------------------------


def _instance(region: str = "eu-west-1", account: str | None = "123456789012") -> CanonicalId:
    return canonical_from_native(
        "ec2", "instance", "i-0abc123def456", region=region, account=account
    )


def test_same_resource_joins() -> None:
    arn_id = parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456")
    native_id = _instance()
    assert safe_join(arn_id, native_id) is True


def test_cross_account_join_is_rejected() -> None:
    assert safe_join(_instance(account="123456789012"), _instance(account="999999999999")) is False


def test_missing_account_never_matches_known_account() -> None:
    # No naive "same region and ID is good enough" join.
    assert safe_join(_instance(account=None), _instance(account="123456789012")) is False


def test_cross_region_join_is_rejected() -> None:
    assert safe_join(_instance(region="eu-west-1"), _instance(region="us-east-1")) is False


def test_global_buckets_join_without_account() -> None:
    left = parse_arn("arn:aws:s3:::acme-customer-data")
    right = canonical_from_native("s3", "bucket", "acme-customer-data")
    assert safe_join(left, right) is True


def test_global_buckets_with_conflicting_accounts_do_not_join() -> None:
    left = refine(parse_arn("arn:aws:s3:::acme-customer-data"), account="123456789012")
    right = refine(parse_arn("arn:aws:s3:::acme-customer-data"), account="999999999999")
    assert safe_join(left, right) is False


def test_cross_partition_join_is_rejected() -> None:
    gov = parse_arn("arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-0abc123def456")
    assert safe_join(gov, _instance()) is False


def test_different_resource_ids_do_not_join() -> None:
    other = canonical_from_native(
        "ec2", "instance", "i-0different", region="eu-west-1", account="123456789012"
    )
    assert safe_join(_instance(), other) is False


def test_terraform_and_aws_ids_do_not_join_by_string() -> None:
    # A Terraform address and an AWS ARN are different namespaces even when
    # their string forms share fragments.
    tf = parse_terraform_address("aws_instance.web")
    aws = parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456")
    assert safe_join(tf, aws) is False
    assert tf.key != aws.key


# --- Stability and refinement ----------------------------------------------


def test_keys_are_stable_across_parses() -> None:
    arn = "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456"
    assert parse_arn(arn) == parse_arn(arn)
    assert parse_arn(arn).key == parse_arn(arn).key


# --- Canonical-key round trip ----------------------------------------------


def test_parse_canonical_is_the_inverse_of_key() -> None:
    arn = "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456"
    cid = parse_arn(arn)
    assert parse_canonical(cid.key) == cid


def test_parse_canonical_reads_absent_region_and_account() -> None:
    cid = parse_canonical("aws/s3/bucket/-/-/data-lake")
    assert cid.region is None
    assert cid.account is None
    assert cid.is_global


def test_parse_canonical_keeps_slashes_in_the_resource_id() -> None:
    # A resource ID may itself contain '/', so only the first five
    # separators split the key.
    cid = parse_canonical("unresolved/-/-/-/-/arn:aws:s3:::data-lake/*")
    assert cid.resource_id == "arn:aws:s3:::data-lake/*"
    assert cid.is_unresolved


def test_parse_canonical_can_take_part_in_a_join() -> None:
    # The reason this inverse exists: a stored key must be parsed before it
    # can be compared, and the parsed form joins exactly like the original.
    cid = parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456")
    assert safe_join(cid, parse_canonical(cid.key)) is True


def test_parse_canonical_rejects_malformed_keys() -> None:
    with pytest.raises(IdParseError, match="six '/'-separated segments"):
        parse_canonical("aws/ec2/instance/i-0abc")
    with pytest.raises(IdParseError, match="empty provider or resource ID"):
        parse_canonical("/ec2/instance/eu-west-1/123456789012/i-0abc")


def test_canonical_id_is_immutable() -> None:
    cid = parse_arn("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def456")
    with pytest.raises(Exception, match="frozen"):
        cid.region = "us-east-1"  # type: ignore[misc]


def test_refine_fills_missing_context_without_overwriting() -> None:
    partial = canonical_from_native("ec2", "instance", "i-0abc", region="eu-west-1")
    refined = refine(partial, account="123456789012")
    assert refined.account == "123456789012"
    assert refined.region == "eu-west-1"
    # Region untouched when not supplied.
    again = refine(refined, account="123456789012")
    assert again == refined


def test_refine_rejects_contradictory_context() -> None:
    cid = canonical_from_native(
        "ec2", "instance", "i-0abc", region="eu-west-1", account="123456789012"
    )
    with pytest.raises(IdParseError, match="refine region"):
        refine(cid, region="us-east-1")
    with pytest.raises(IdParseError, match="refine account"):
        refine(cid, account="999999999999")


def test_refined_ids_join_with_fully_known_ids() -> None:
    partial = canonical_from_native("ec2", "instance", "i-0abc123def456", region="eu-west-1")
    refined = refine(partial, account="123456789012")
    assert safe_join(refined, _instance()) is True
