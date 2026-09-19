"""Canonical resource-ID normalization.

Normalization is an explicit boundary: adapters must not join strings ad hoc.
Every identifier that enters the system — an AWS ARN, a native resource ID
returned by an API, a Terraform address, or an external reference the tool
cannot fully resolve — passes through this module and becomes a
:class:`CanonicalId`. The original source-native identifier is always
preserved alongside (in the model fields of ``Resource``/``Evidence``, never
overwritten by parsing).

Safety properties, all enforced structurally:

- The canonical key embeds provider (including AWS partition), service,
  resource type, region, and account, so two identifiers only produce the
  same key when they genuinely denote the same resource.
- Unresolved references (wildcard ARNs, free-form external targets) get the
  ``unresolved`` provider and can never equal a resolved ID.
- :func:`safe_join` refuses naive cross-account and cross-region joins: for
  region-scoped resources, both region and account must match exactly, and a
  missing account never matches a known one.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

UNRESOLVED_PROVIDER = "unresolved"
TERRAFORM_PROVIDER = "terraform"

#: Services whose resources are global (region-less) in AWS.
GLOBAL_SERVICES: frozenset[str] = frozenset({"s3", "iam", "cloudfront", "route53", "waf"})

#: The only ARN partitions accepted; anything else is malformed, not guessed.
KNOWN_PARTITIONS: frozenset[str] = frozenset(
    {"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f"}
)

#: Default resource type for ARNs whose resource part carries no type
#: (currently only bare S3 bucket names).
_BARE_RESOURCE_TYPES: dict[str, str] = {"s3": "bucket"}

_ARN_RE = re.compile(
    r"^arn:(?P<partition>[a-z0-9-]+):(?P<service>[a-z0-9-]+):"
    r"(?P<region>[a-z0-9-]*):(?P<account>[0-9]{0,12}):(?P<resource>.+)$"
)

# A full Terraform resource address: optional module path (module.name[.key].…),
# optional "data." marker, then provider_type.name with an optional index.
_TF_ADDRESS_RE = re.compile(
    r"^(?:module\.[A-Za-z_][A-Za-z0-9_-]*(?:\[[^\]]+\])?\.)*"
    r"(?:data\.)?[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*"
    r"(?:\[[^\]]+\])?$"
)

_WILDCARD_CHARS = ("*", "?")


class IdParseError(ValueError):
    """Raised when an identifier is malformed or cannot be normalized."""


class CanonicalId(BaseModel):
    """A normalized, immutable resource identity.

    Attributes:
        provider: identity namespace — an AWS partition (``aws``,
            ``aws-cn``, ``aws-us-gov``), ``terraform``, or ``unresolved``.
        service: provider-level service (``ec2``, ``s3``, …; for Terraform
            the provider named inside the type, e.g. ``aws``).
        resource_type: service-level type (``instance``, ``bucket``, …).
        resource_id: the identifying fragment within provider/service/type.
        region: AWS region, or ``None`` for global services and Terraform.
        account: AWS account ID, or ``None`` when unknown.
    """

    model_config = ConfigDict(frozen=True)

    provider: str
    service: str
    resource_type: str
    resource_id: str
    region: str | None = None
    account: str | None = None

    @field_validator("provider", "service", "resource_type", "resource_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("identifier components must be non-empty")
        return value

    @field_validator("region", "account")
    @classmethod
    def _optional_means_absent(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            return None
        return value

    @property
    def key(self) -> str:
        """Stable canonical key; ``-`` marks absent region/account."""
        return "/".join(
            [
                self.provider,
                self.service,
                self.resource_type,
                self.region or "-",
                self.account or "-",
                self.resource_id,
            ]
        )

    def __str__(self) -> str:
        return self.key

    @property
    def is_unresolved(self) -> bool:
        return self.provider == UNRESOLVED_PROVIDER

    @property
    def is_global(self) -> bool:
        return self.provider != UNRESOLVED_PROVIDER and self.service in GLOBAL_SERVICES


def parse_arn(arn: str) -> CanonicalId:
    """Parse a concrete AWS ARN into a canonical ID.

    Raises:
        IdParseError: if the ARN is malformed, or contains wildcards (use
            :func:`unresolved` for policy patterns and other patterns).
    """
    if any(char in arn for char in _WILDCARD_CHARS):
        raise IdParseError(
            f"ARN contains wildcards and denotes a pattern, not a resource: {arn!r}; "
            "use unresolved() for pattern references"
        )
    match = _ARN_RE.match(arn)
    if match is None:
        raise IdParseError(f"malformed ARN: {arn!r}")
    if match.group("partition") not in KNOWN_PARTITIONS:
        raise IdParseError(f"unknown ARN partition {match.group('partition')!r}: {arn!r}")
    service = match.group("service")
    resource = match.group("resource")
    if resource.startswith(":"):
        # e.g. "arn:aws:s3:eu-west-1:::bucket" — the resource part begins
        # after the empty account field's separator.
        resource = resource[1:]
    if "/" in resource:
        resource_type, resource_id = resource.split("/", 1)
    elif ":" in resource:
        resource_type, resource_id = resource.split(":", 1)
    else:
        resource_type, resource_id = _BARE_RESOURCE_TYPES.get(service, "resource"), resource
    # Global services are region-less regardless of what the ARN claimed.
    region = None if service in GLOBAL_SERVICES else match.group("region") or None
    account = match.group("account") or None
    return CanonicalId(
        provider=match.group("partition"),
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        account=account,
    )


def parse_canonical(key: str) -> CanonicalId:
    """Parse a canonical key (``CanonicalId.key``) back into a CanonicalId.

    The exact inverse of :attr:`CanonicalId.key`: six ``/``-separated
    segments, ``-`` marking an absent region or account, and everything after
    the fifth separator is the resource ID (it may itself contain ``/``).
    Needed wherever a stored canonical key must take part in a
    :func:`safe_join` decision — a key alone cannot be compared, only parsed.
    """
    segments = key.split("/", 5)
    if len(segments) != 6:
        raise IdParseError(
            f"a canonical key has six '/'-separated segments, got {len(segments)}: {key!r}"
        )
    provider, service, resource_type, region, account, resource_id = segments
    if not provider.strip() or not resource_id.strip():
        raise IdParseError(f"canonical key has empty provider or resource ID: {key!r}")
    return CanonicalId(
        provider=provider,
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        region=None if region == "-" else region,
        account=None if account == "-" else account,
    )


def canonical_from_native(
    service: str,
    resource_type: str,
    resource_id: str,
    *,
    region: str | None = None,
    account: str | None = None,
    provider: str = "aws",
) -> CanonicalId:
    """Build a canonical ID from a native resource ID plus scan context.

    The caller supplies the region/account context of the scan session; this
    function refuses to guess. Region-scoped services require an explicit
    region, and wildcards are rejected — pattern references must go through
    :func:`unresolved`.
    """
    if any(char in resource_id for char in _WILDCARD_CHARS):
        raise IdParseError(
            f"native resource ID contains wildcards: {resource_id!r}; "
            "use unresolved() for pattern references"
        )
    if provider != UNRESOLVED_PROVIDER and service not in GLOBAL_SERVICES and not region:
        raise IdParseError(
            f"{service}/{resource_type} resources are region-scoped; "
            "an explicit region is required and none was supplied"
        )
    if service in GLOBAL_SERVICES:
        region = None
    return CanonicalId(
        provider=provider,
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        region=region or None,
        account=account or None,
    )


def parse_terraform_address(address: str) -> CanonicalId:
    """Parse a Terraform resource address into a canonical ID.

    Accepts ``aws_instance.web``, module paths (``module.vpc.aws_instance.web``),
    data sources (``data.aws_ami.ubuntu``), and indices (``[0]``, ``["key"]``,
    ``[*]``). The full original address is preserved as ``resource_id``.
    """
    if not _TF_ADDRESS_RE.match(address):
        raise IdParseError(f"malformed Terraform address: {address!r}")
    body = address
    if body.endswith("]") and "[" in body:
        body = body[: body.rindex("[")]
    segments = body.split(".")
    if segments[0] == "data" and len(segments) > 2:
        segments = segments[1:]
    tf_type, name = segments[-2], segments[-1]
    if tf_type in ("module", "data"):
        raise IdParseError(f"address denotes a module or data source, not a resource: {address!r}")
    module_path = segments[:-2]
    # A module path is repeated "module.NAME" pairs.
    if len(module_path) % 2 != 0 or any(
        module_path[i] != "module" for i in range(0, len(module_path), 2)
    ):
        raise IdParseError(
            f"only 'module.NAME' path segments may precede a resource address: {address!r}"
        )
    if len(tf_type) < 2 or len(name) < 1:
        raise IdParseError(f"malformed Terraform address: {address!r}")
    service = tf_type.split("_", 1)[0] if "_" in tf_type else "terraform"
    return CanonicalId(
        provider=TERRAFORM_PROVIDER,
        service=service,
        resource_type=tf_type,
        resource_id=address,
        region=None,
        account=None,
    )


def unresolved(reference: str) -> CanonicalId:
    """Represent an external target the tool cannot fully resolve.

    Examples: wildcard policy ARNs (``arn:aws:s3:::data-*``), hostnames,
    principals from other accounts. An unresolved ID never equals a resolved
    one — it marks "needs human attention", not "no dependency".
    """
    if not reference.strip():
        raise IdParseError("an unresolved reference must carry the raw target text")
    return CanonicalId(
        provider=UNRESOLVED_PROVIDER,
        service="-",
        resource_type="-",
        resource_id=reference,
    )


def safe_join(a: CanonicalId, b: CanonicalId) -> bool:
    """True only when ``a`` and ``b`` may denote the same concrete resource.

    This is the single place join decisions are made, and it is deliberately
    conservative:

    - Unresolved references never join with anything.
    - Provider (including AWS partition), service, type, and ID must match.
    - Region-scoped resources must match on region AND account; a missing
      account never matches a known one (no naive cross-account joins).
    - Global resources join when accounts are equal or either is unknown.
    """
    if a.is_unresolved or b.is_unresolved:
        return False
    if (a.provider, a.service, a.resource_type, a.resource_id) != (
        b.provider,
        b.service,
        b.resource_type,
        b.resource_id,
    ):
        return False
    if a.is_global or b.is_global:
        accounts_conflict = (
            a.account is not None and b.account is not None and a.account != b.account
        )
        return not accounts_conflict
    if a.region != b.region:
        return False
    return a.account == b.account


def refine(
    cid: CanonicalId, *, region: str | None = None, account: str | None = None
) -> CanonicalId:
    """Fill in missing region/account on a canonical ID, never overwrite.

    Later phases learn scan context (e.g. the account from STS) that an
    adapter could not know when it first built an ID. Refining is how that
    context is applied. Supplying a value that contradicts an existing one
    raises — a contradiction means two sources disagree about identity, which
    must surface rather than be silently resolved.
    """
    if cid.region is not None and region is not None and cid.region != region:
        raise IdParseError(
            f"cannot refine region of {cid.key}: it is {cid.region!r}, "
            f"refusing to change to {region!r}"
        )
    if cid.account is not None and account is not None and cid.account != account:
        raise IdParseError(
            f"cannot refine account of {cid.key}: it is {cid.account!r}, "
            f"refusing to change to {account!r}"
        )
    return CanonicalId(
        provider=cid.provider,
        service=cid.service,
        resource_type=cid.resource_type,
        resource_id=cid.resource_id,
        region=cid.region or region,
        account=cid.account or account,
    )
