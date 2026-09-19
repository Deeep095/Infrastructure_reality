"""Hidden-dependency detection: a narrow projection of UNDOCUMENTED findings.

A hidden dependency is an *observed* relationship with no declared
counterpart — the one case the build brief calls "the only basis for
hidden-dependency reporting". The projection is deliberately narrow; a
finding qualifies only when all of the following hold:

- its conclusion is ``UNDOCUMENTED`` (observed, not declared, and Terraform
  was actually consulted — the conclusion already encodes that);
- both its canonical source and target are resolved identities. An
  unresolved reference is "needs human attention", never a hidden
  dependency;
- at least one *observed* evidence record (AWS or CloudTrail) backs it.
  Permission evidence alone never makes a hidden dependency.

The confidence band is derived from the qualitative strengths of the
observed evidence — strong / moderate / weak with a text rationale. No
numeric score is fabricated anywhere: an invented decimal would carry
precision the evidence does not have.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from reality.domain.enums import (
    Conclusion,
    EvidenceStrength,
    RelationshipType,
)
from reality.domain.ids import UNRESOLVED_PROVIDER
from reality.domain.models import Evidence
from reality.services.reconcile import OBSERVED_SOURCES, ReconciledRelationship
from reality.storage.repositories import ScanStore


class ConfidenceBand(StrEnum):
    """A qualitative band derived from evidence strengths — never a number."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class HiddenDependency(BaseModel):
    """One observed relationship whose declared counterpart is missing."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    source_canonical_id: str
    target_canonical_id: str
    relationship_type: RelationshipType
    band: ConfidenceBand
    rationale: str
    evidence_ids: tuple[str, ...] = ()


#: Strongest-first: the strongest observed evidence sets the band.
_STRENGTH_ORDER: tuple[EvidenceStrength, ...] = (
    EvidenceStrength.HIGH,
    EvidenceStrength.MEDIUM,
    EvidenceStrength.LOW,
    EvidenceStrength.UNKNOWN,
)

_BAND_BY_STRENGTH: dict[EvidenceStrength, ConfidenceBand] = {
    EvidenceStrength.HIGH: ConfidenceBand.STRONG,
    EvidenceStrength.MEDIUM: ConfidenceBand.MODERATE,
}


def _is_unresolved(canonical_id: str) -> bool:
    return canonical_id.startswith(f"{UNRESOLVED_PROVIDER}/")


def _strongest(records: Sequence[Evidence]) -> EvidenceStrength:
    strengths = {record.strength for record in records}
    for strength in _STRENGTH_ORDER:
        if strength in strengths:
            return strength
    return EvidenceStrength.UNKNOWN  # pragma: no cover - unreachable for non-empty input


def _band(records: Sequence[Evidence]) -> ConfidenceBand:
    return _BAND_BY_STRENGTH.get(_strongest(records), ConfidenceBand.WEAK)


def _rationale(
    item: ReconciledRelationship, records: Sequence[Evidence], band: ConfidenceBand
) -> str:
    sources = ", ".join(sorted({record.source.value for record in records}))
    strongest = _strongest(records)
    text = (
        f"observed by {sources}: {len(records)} evidence record(s), strongest "
        f"{strongest.value}, back {item.source_canonical_id} -> "
        f"{item.target_canonical_id} ({item.relationship_type.value}); no Terraform "
        "declaration matches this canonical triple even though Terraform was "
        "consulted, so the declared counterpart is missing rather than unread"
    )
    if band is ConfidenceBand.WEAK:
        text += (
            "; the supporting evidence is low-strength, so treat this as a lead "
            "to verify, not a conclusion"
        )
    return text


class HiddenDependencyService:
    """Projects UNDOCUMENTED reconciliation findings into hidden dependencies."""

    def __init__(self, store: ScanStore) -> None:
        self._store = store

    def detect(
        self, relationships: Sequence[ReconciledRelationship]
    ) -> tuple[HiddenDependency, ...]:
        """Select the hidden dependencies from reconciliation output, in order."""
        reported: list[HiddenDependency] = []
        for item in relationships:
            if item.conclusion != Conclusion.UNDOCUMENTED:
                continue
            if _is_unresolved(item.source_canonical_id) or _is_unresolved(item.target_canonical_id):
                continue
            observed = [
                record
                for evidence_id in item.evidence_ids
                if (record := self._store.evidence.get(evidence_id)) is not None
                and record.source in OBSERVED_SOURCES
            ]
            if not observed:
                continue
            reported.append(
                HiddenDependency(
                    finding_id=item.finding_id,
                    source_canonical_id=item.source_canonical_id,
                    target_canonical_id=item.target_canonical_id,
                    relationship_type=item.relationship_type,
                    band=_band(observed),
                    rationale=_rationale(item, observed, _band(observed)),
                    evidence_ids=tuple(record.id for record in observed),
                )
            )
        return tuple(reported)
