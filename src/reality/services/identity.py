"""Evidence-backed identity joins between the declared and observed worlds.

Terraform declarations live in the ``terraform/`` namespace (their address is
their ID) and AWS observations in the ``aws/`` namespace, and the two never
merge implicitly. This module is where they join *explicitly*: a Terraform
state resource carries the ARN and/or native ID of the real resource it
manages, and when the same scan observed an AWS resource with that exact
identity, the two canonical IDs are recorded as one mapping — with the
evidence that joined them and the reason, so the join is auditable rather
than assumed.

Rules, all deliberately conservative:

- **The state ARN is authoritative.** An ARN embeds region and account, so it
  joins through :func:`~reality.domain.ids.safe_join` — the single place join
  decisions are made. When a state resource carries a parseable ARN, only the
  ARN can join it; if nothing observed matches, the resource stays unmapped
  (a native ID that happens to match something else is a contradiction, not
  a fallback).
- **A native ID joins only without a usable ARN**, only against the same
  resource type, and only when exactly one observed resource shares it — an
  ambiguous native ID maps nothing.
- **Names are never matched.** A ``name`` that looks similar proves nothing
  about identity; no code path here reads the name field.
- **Only state declarations join.** A plan's ``planned_values`` describe
  future resources; joining them to currently observed ones would be wrong.
- **Both identities are preserved.** The mapping records each canonical ID
  alongside the other; neither replaces the other anywhere.
- **One scan, one join.** Mappings are computed from the resources a single
  scan collected, so a join is always backed by both sides of the same scan
  context — never by a stale observation from an earlier run.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from reality.domain.enums import (
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    MappingBasis,
)
from reality.domain.ids import (
    TERRAFORM_PROVIDER,
    UNRESOLVED_PROVIDER,
    CanonicalId,
    IdParseError,
    parse_arn,
    parse_canonical,
    safe_join,
)
from reality.domain.models import Evidence, IdentityMapping, Resource


@dataclass(frozen=True)
class ComputedMapping:
    """One identity join plus the evidence record that backs it.

    A frozen pair so scans and tests can compare two computations for
    equality — the same inputs must yield the same joins.
    """

    mapping: IdentityMapping
    evidence: Evidence


def compute_identity_mappings(
    resources: Sequence[Resource],
) -> tuple[ComputedMapping, ...]:
    """Join Terraform state declarations to observed AWS resources.

    Takes every resource one scan collected, splits it into the declared
    (state-sourced Terraform) and observed (AWS-partition) sides, and returns
    one :class:`ComputedMapping` per exact-identity join, in deterministic
    order. Ambiguous joins map nothing: two declarations claiming one
    observed resource, or one native ID matching several, are recorded as
    the absence of a mapping rather than a guess.
    """
    declared = sorted(
        (
            resource
            for resource in resources
            if resource.provider == TERRAFORM_PROVIDER
            and resource.source == EvidenceSource.TERRAFORM_STATE
        ),
        key=lambda resource: resource.canonical_id,
    )
    observed = [
        resource
        for resource in resources
        if resource.provider not in (TERRAFORM_PROVIDER, UNRESOLVED_PROVIDER)
    ]

    candidates: list[ComputedMapping] = []
    for resource in declared:
        computed = _match(resource, observed)
        if computed is not None:
            candidates.append(computed)

    # One observed resource claimed by two declarations is ambiguous — the
    # state disagrees with itself, and no join is safe. Drop every claim on
    # such a resource, deterministically.
    claims: dict[str, list[ComputedMapping]] = {}
    for computed in candidates:
        claims.setdefault(computed.mapping.aws_canonical_id, []).append(computed)
    joined = [
        computed for computed in candidates if len(claims[computed.mapping.aws_canonical_id]) == 1
    ]
    return tuple(sorted(joined, key=lambda computed: computed.mapping.terraform_canonical_id))


def _match(declared: Resource, observed: Sequence[Resource]) -> ComputedMapping | None:
    """The one join for a declared resource, or ``None`` — never a guess."""
    if declared.arn is not None:
        try:
            arn_id: CanonicalId | None = parse_arn(declared.arn)
        except IdParseError:
            arn_id = None  # an unparseable ARN cannot join; the native ID may
        if arn_id is not None:
            matches = [
                resource
                for resource in observed
                if safe_join(arn_id, parse_canonical(resource.canonical_id))
            ]
            if len(matches) == 1:
                return _build(declared, matches[0], MappingBasis.ARN, declared.arn)
            return None  # zero or several: the authoritative ARN maps nothing
    if declared.native_id is not None:
        matches = [
            resource
            for resource in observed
            if resource.resource_type == declared.resource_type
            and resource.native_id == declared.native_id
        ]
        if len(matches) == 1:
            return _build(declared, matches[0], MappingBasis.NATIVE_ID, declared.native_id)
    return None


def _build(
    declared: Resource, observed: Resource, basis: MappingBasis, matched_value: str
) -> ComputedMapping:
    """Assemble the mapping and its backing evidence for one exact join."""
    field = "arn" if basis is MappingBasis.ARN else "id"
    address = declared.terraform_address or declared.canonical_id
    reason = (
        f"terraform state declares {address} with {field} {matched_value!r}, which "
        f"denotes the same resource AWS reported as {observed.canonical_id}; "
        "an exact identifier match, never a name match"
    )
    evidence_id = f"identity:{declared.canonical_id}:{observed.canonical_id}"
    return ComputedMapping(
        mapping=IdentityMapping(
            terraform_canonical_id=declared.canonical_id,
            aws_canonical_id=observed.canonical_id,
            basis=basis,
            matched_value=matched_value,
            evidence_id=evidence_id,
            reason=reason,
        ),
        evidence=Evidence(
            id=evidence_id,
            source=EvidenceSource.TERRAFORM_STATE,
            type=EvidenceType.IDENTITY_MATCH,
            observed_at=None,
            actor="terraform",
            source_ref=address,
            target_ref=observed.canonical_id,
            source_canonical_id=declared.canonical_id,
            target_canonical_id=observed.canonical_id,
            strength=EvidenceStrength.HIGH,
            raw_locator=f"terraform_state#{address}.values.{field}",
            explanation=reason,
        ),
    )


__all__ = ["ComputedMapping", "compute_identity_mappings"]
