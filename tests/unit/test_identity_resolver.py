"""The identity resolver must follow edges across compatible identities.

The bug this guards against: a scan stored the S3 bucket account-qualified
(``aws/s3/bucket/-/123456789012/data-lake``) while every edge that references it
was recorded accountless (``aws/s3/bucket/-/-/data-lake``). Exact-string
traversal never matched them, so the bucket reported ``dependents: none`` and
``risk: low`` — it looked safe to delete when a role depended on it.
"""

from __future__ import annotations

from reality.domain.enums import RelationshipType, ResourceType
from reality.domain.ids import parse_canonical, resolve_compatible
from reality.domain.models import Relationship, Resource
from reality.services.graph import IdentityResolver


def _resource(canonical_id: str, resource_type: ResourceType) -> Resource:
    return Resource(
        canonical_id=canonical_id,
        provider=canonical_id.split("/")[0],
        resource_type=resource_type,
        name=canonical_id.split("/")[-1],
    )


def _edge(source: str, target: str) -> Relationship:
    return Relationship(
        source_canonical_id=source,
        target_canonical_id=target,
        type=RelationshipType.DEPENDS_ON,
        origin="aws_observed",
        evidence_ids=("ev:1",),
    )


class TestResolveCompatible:
    def test_accountless_s3_arn_resolves_to_account_qualified_bucket(self) -> None:
        accountless = parse_canonical("aws/s3/bucket/-/-/data-lake")
        qualified = parse_canonical("aws/s3/bucket/-/123456789012/data-lake")
        assert resolve_compatible(accountless, qualified)
        assert resolve_compatible(qualified, accountless)

    def test_conflicting_accounts_refuse_the_join(self) -> None:
        a = parse_canonical("aws/s3/bucket/-/111111111111/data-lake")
        b = parse_canonical("aws/s3/bucket/-/222222222222/data-lake")
        assert not resolve_compatible(a, b)

    def test_accountless_iam_role_does_not_resolve(self) -> None:
        # A role name is not unique across accounts, so the account is part of
        # identity — unlike an S3 bucket name.
        accountless = parse_canonical("aws/iam/role/-/-/cleanup_role")
        qualified = parse_canonical("aws/iam/role/-/123456789012/cleanup_role")
        assert not resolve_compatible(accountless, qualified)

    def test_unresolved_never_resolves(self) -> None:
        unresolved = parse_canonical("unresolved/-/-/-/-/*")
        bucket = parse_canonical("aws/s3/bucket/-/123456789012/data-lake")
        assert not resolve_compatible(unresolved, bucket)

    def test_different_type_never_resolves(self) -> None:
        bucket = parse_canonical("aws/s3/bucket/-/-/data-lake")
        key = parse_canonical("aws/kms/key/-/-/data-lake")
        assert not resolve_compatible(bucket, key)


class TestIdentityResolver:
    def test_resolve_finds_the_stored_bucket(self) -> None:
        bucket = _resource("aws/s3/bucket/-/123456789012/data-lake", ResourceType.S3_BUCKET)
        resolver = IdentityResolver([bucket])
        assert resolver.resolve("aws/s3/bucket/-/-/data-lake") == (
            "aws/s3/bucket/-/123456789012/data-lake",
        )

    def test_resolve_returns_self_when_nothing_matches(self) -> None:
        bucket = _resource("aws/s3/bucket/-/123456789012/data-lake", ResourceType.S3_BUCKET)
        resolver = IdentityResolver([bucket])
        assert resolver.resolve("aws/s3/bucket/-/999999999999/other") == (
            "aws/s3/bucket/-/999999999999/other",
        )

    def test_incoming_finds_edges_recorded_against_the_accountless_id(self) -> None:
        bucket = _resource("aws/s3/bucket/-/123456789012/data-lake", ResourceType.S3_BUCKET)
        role = _resource("aws/iam/role/-/123456789012/processor_role", ResourceType.IAM_ROLE)
        edge = _edge(role.canonical_id, "aws/s3/bucket/-/-/data-lake")
        resolver = IdentityResolver([bucket, role], [edge])
        assert resolver.incoming("aws/s3/bucket/-/123456789012/data-lake") == (edge,)

    def test_outgoing_finds_edges_from_a_compatible_source(self) -> None:
        bucket = _resource("aws/s3/bucket/-/123456789012/data-lake", ResourceType.S3_BUCKET)
        role = _resource("aws/iam/role/-/123456789012/processor_role", ResourceType.IAM_ROLE)
        edge = _edge(role.canonical_id, "aws/s3/bucket/-/-/data-lake")
        resolver = IdentityResolver([bucket, role], [edge])
        assert resolver.outgoing(role.canonical_id) == (edge,)

    def test_unresolved_edges_are_not_returned(self) -> None:
        bucket = _resource("aws/s3/bucket/-/123456789012/data-lake", ResourceType.S3_BUCKET)
        wildcard = _edge("aws/iam/role/-/123456789012/processor_role", "unresolved/-/-/-/-/*")
        resolver = IdentityResolver([bucket], [wildcard])
        assert resolver.incoming(bucket.canonical_id) == ()
