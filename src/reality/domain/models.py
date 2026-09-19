"""Immutable domain contracts.

Rules that hold across every model here:

- All models are frozen; nothing in the domain mutates in place.
- Evidence is stored separately from conclusions (:class:`Evidence` vs
  :class:`Finding`); nothing about an evidence item implies a conclusion.
- Source-native identifiers (native ID, ARN, Terraform address) are always
  preserved in their own fields, next to — never replaced by — the canonical
  ID string.
- Strength and coverage are qualitative, never numeric.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from reality.domain.enums import (
    ChangeAction,
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    ImpactBasis,
    MappingBasis,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Resource(BaseModel):
    """A resource discovered from some source, in its source-native form.

    ``canonical_id`` is the stable key produced by ``reality.domain.ids``;
    ``native_id``/``arn``/``terraform_address`` preserve the identifiers the
    source actually used.
    """

    model_config = ConfigDict(frozen=True)

    canonical_id: str
    resource_type: ResourceType
    provider: str

    @field_validator("canonical_id", "provider")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    native_id: str | None = None
    arn: str | None = None
    terraform_address: str | None = None
    region: str | None = None
    account: str | None = None
    name: str | None = None
    discovered_at: datetime = Field(default_factory=_utcnow)
    source: EvidenceSource | None = None


class Relationship(BaseModel):
    """A directed claim that source relates to target.

    A relationship is a candidate until reconciliation turns it into a
    conclusion; the evidence IDs back the claim without deciding it.
    """

    model_config = ConfigDict(frozen=True)

    source_canonical_id: str
    target_canonical_id: str
    type: RelationshipType
    origin: RelationshipOrigin
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    evidence_ids: tuple[str, ...] = ()


class Evidence(BaseModel):
    """One observed fact backing one or more relationships.

    Field obligations (each must be retained, per the domain contract):

    - ``id``: stable evidence ID.
    - ``source``: which adapter produced it.
    - ``type``: the concrete shape of the fact.
    - ``observed_at``: when the fact was observed (``None`` only when the
      source carries no meaningful time, e.g. a config file).
    - ``actor``: who/what acted or declared (e.g. a CloudTrail principal).
    - ``source_ref``/``target_ref``: the raw source-native references as
      they appeared; canonical IDs, when resolvable, are kept alongside.
    - ``strength``: qualitative HIGH/MEDIUM/LOW/UNKNOWN — never numeric.
    - ``raw_locator``: pointer back into the raw data (file path + JSON
      pointer, event ID, …).
    - ``explanation``: human-readable text saying what the fact is.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    source: EvidenceSource
    type: EvidenceType
    observed_at: datetime | None = None
    actor: str | None = None
    source_ref: str
    target_ref: str
    source_canonical_id: str | None = None
    target_canonical_id: str | None = None
    strength: EvidenceStrength
    raw_locator: str
    explanation: str


class Coverage(BaseModel):
    """Whether an evidence source could actually be consulted.

    ``UNAVAILABLE`` is not "no dependency found" — it means the input was
    missing (e.g. CloudTrail history exhausted), and conclusions that would
    have needed it must come out ``UNKNOWN``.
    """

    model_config = ConfigDict(frozen=True)

    source: EvidenceSource
    status: CoverageStatus
    reason: str
    region: str | None = None
    recorded_at: datetime = Field(default_factory=_utcnow)


class TerraformChange(BaseModel):
    """What an exported Terraform plan says will happen to one resource."""

    model_config = ConfigDict(frozen=True)

    address: str
    tf_resource_type: str
    actions: tuple[ChangeAction, ...]

    @field_validator("address", "tf_resource_type")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("actions")
    @classmethod
    def _at_least_one_action(cls, value: tuple[ChangeAction, ...]) -> tuple[ChangeAction, ...]:
        if not value:
            raise ValueError("a change must record at least one action")
        return value

    canonical_id: str | None = None


class Finding(BaseModel):
    """A reconciliation conclusion about one resource or relationship.

    The conclusion semantics are frozen in :class:`~reality.domain.enums.Conclusion`;
    ``evidence_ids`` and ``unavailable_sources`` keep the basis auditable.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    subject_canonical_id: str
    conclusion: Conclusion
    explanation: str
    evidence_ids: tuple[str, ...] = ()
    unavailable_sources: tuple[EvidenceSource, ...] = ()


class IdentityMapping(BaseModel):
    """An evidence-backed join between a Terraform declaration and the AWS
    resource it denotes.

    Both identities are preserved — a mapping never replaces one canonical ID
    with the other, it records that the two denote the same real resource. The
    join is always an exact identifier match (the state's ARN, or its native
    ID when no usable ARN exists): names are never matched, fuzzily or
    otherwise. ``evidence_id`` points at the evidence record backing the join
    and ``reason`` says, in plain text, why the two identities were joined.
    """

    model_config = ConfigDict(frozen=True)

    terraform_canonical_id: str
    aws_canonical_id: str
    basis: MappingBasis
    matched_value: str
    evidence_id: str
    reason: str

    @field_validator("terraform_canonical_id", "aws_canonical_id", "matched_value", "evidence_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ImpactItem(BaseModel):
    """One resource inside a blast radius, with the path that reached it."""

    model_config = ConfigDict(frozen=True)

    canonical_id: str
    path: tuple[str, ...]  # canonical IDs from subject to this resource
    depth: int = Field(ge=1)


class ImpactResult(BaseModel):
    """The outcome of a blast-radius computation.

    This is a report, not an action: it lists what would be affected and
    what could not be determined (``notes`` carries the ``UNKNOWN`` coverage
    caveats). It never proposes automatic deletion.
    """

    model_config = ConfigDict(frozen=True)

    subject_canonical_id: str
    basis: ImpactBasis
    affected: tuple[ImpactItem, ...] = ()
    notes: tuple[str, ...] = ()
    computed_at: datetime = Field(default_factory=_utcnow)
