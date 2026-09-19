"""Domain contracts for reality.

The domain layer is pure: Pydantic v2 models and enums, no I/O, no storage,
no adapters. Everything here is immutable; later phases compose these
contracts into scans, reconciliation, and simulation.
"""

from reality.domain.enums import (
    ChangeAction,
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    ImpactBasis,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.ids import (
    CanonicalId,
    IdParseError,
    canonical_from_native,
    parse_arn,
    parse_terraform_address,
    refine,
    safe_join,
    unresolved,
)
from reality.domain.models import (
    Coverage,
    Evidence,
    Finding,
    ImpactItem,
    ImpactResult,
    Relationship,
    Resource,
    TerraformChange,
)

__all__ = [
    "CanonicalId",
    "ChangeAction",
    "Conclusion",
    "Coverage",
    "CoverageStatus",
    "Evidence",
    "EvidenceSource",
    "EvidenceStrength",
    "EvidenceType",
    "Finding",
    "IdParseError",
    "ImpactBasis",
    "ImpactItem",
    "ImpactResult",
    "Relationship",
    "RelationshipOrigin",
    "RelationshipType",
    "Resource",
    "ResourceType",
    "TerraformChange",
    "canonical_from_native",
    "parse_arn",
    "parse_terraform_address",
    "refine",
    "safe_join",
    "unresolved",
]
