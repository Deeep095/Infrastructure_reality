"""Read-only blast-radius traversal over stored relationships.

Everything here answers "what would be affected?" from the local database
alone. No adapter runs, no client is constructed, and nothing is written:
``impact`` reports on a stored resource, and ``simulate`` reads a local
Terraform plan JSON through the Terraform adapter (which parses files, never
runs Terraform) and reports on its delete/replace targets.

Traversal is a bounded breadth-first walk *against* relationship direction —
a dependent is the source of an edge pointing at a node already inside the
radius. The first (shortest) path to a resource wins, parallel edges into the
radius are aggregated, and cycles stop at the first revisit, so the result is
deterministic for a given database.

Risk bands are documented, not scored:

- ``HIGH``    any dependent is UNDOCUMENTED (observed with no declaration) —
              the plan would touch something the declared world does not know.
- ``MEDIUM``  declared (or otherwise known) dependents, or no dependents
              while relevant coverage is missing — absence of evidence is not
              evidence of absence.
- ``LOW``     no known dependent, and the sources that could have revealed one
              for this subject were actually consulted. A Terraform-namespace
              subject can only carry declared dependents, so the declared side
              (state *or* plan) suffices; any other subject may also carry
              observed and permission dependents, so both sides are required.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reality.adapters.terraform import TerraformAdapter
from reality.domain.enums import (
    ChangeAction,
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    ImpactBasis,
)
from reality.domain.ids import TERRAFORM_PROVIDER
from reality.domain.models import Relationship, Resource, TerraformChange
from reality.services.reconcile import finding_id
from reality.services.scan import ScanInputError
from reality.storage.repositories import ScanStore

#: The traversal bound when the caller does not choose one.
DEFAULT_DEPTH = 3

#: Sources that can store relationships targeting a Terraform-namespace
#: subject (only the declared world ever targets those canonical IDs).
_DECLARED_SIDE = frozenset({EvidenceSource.TERRAFORM_STATE, EvidenceSource.TERRAFORM_PLAN})

#: Sources that can store relationships targeting any other subject.
_OBSERVED_SIDE = frozenset(
    {EvidenceSource.AWS_RESOURCES, EvidenceSource.CLOUDTRAIL, EvidenceSource.IAM}
)

#: Simulate acts on destructive-looking actions only; an update is not a
#: removal, and this classifier never applies anything regardless.
_DESTRUCTIVE_ACTIONS = frozenset({ChangeAction.DELETE, ChangeAction.REPLACE})


class RiskLevel(StrEnum):
    """The documented blast-radius band; deliberately not a number."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DependentKind(StrEnum):
    """How well-documented one dependent's dependency is."""

    DOCUMENTED = "documented"  # declared in Terraform (CONFIRMED or DECLARED_ONLY)
    UNDOCUMENTED = "undocumented"  # observed with no declaration
    POSSIBLE = "possible"  # IAM permission, no observed usage
    UNKNOWN = "unknown"  # conclusion blocked by coverage, or never reconciled


_KIND_BY_CONCLUSION: dict[Conclusion, DependentKind] = {
    Conclusion.CONFIRMED: DependentKind.DOCUMENTED,
    Conclusion.DECLARED_ONLY: DependentKind.DOCUMENTED,
    Conclusion.UNDOCUMENTED: DependentKind.UNDOCUMENTED,
    Conclusion.POSSIBLE: DependentKind.POSSIBLE,
    Conclusion.UNKNOWN: DependentKind.UNKNOWN,
}

#: Most cautionary first: when parallel edges disagree, the most cautionary
#: classification wins, because a blast radius is a worst-case report.
_KIND_SEVERITY: tuple[DependentKind, ...] = (
    DependentKind.UNDOCUMENTED,
    DependentKind.UNKNOWN,
    DependentKind.POSSIBLE,
    DependentKind.DOCUMENTED,
)

_RANK: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
}


class Dependent(BaseModel):
    """One resource inside a blast radius, and why it is there."""

    model_config = ConfigDict(frozen=True)

    canonical_id: str
    path: tuple[str, ...]  # canonical IDs from the subject to this dependent
    depth: int
    kind: DependentKind
    conclusion: Conclusion | None = None  # the finding behind `kind`, if any
    provenance: tuple[str, ...] = ()  # sorted relationship origins on the path
    evidence_ids: tuple[str, ...] = ()  # evidence backing every edge on the path


class ImpactReport(BaseModel):
    """The blast radius of one subject: dependents, risk, and caveats."""

    model_config = ConfigDict(frozen=True)

    subject_canonical_id: str
    basis: ImpactBasis
    depth: int
    risk: RiskLevel
    dependents: tuple[Dependent, ...] = ()
    notes: tuple[str, ...] = ()


class SimulatedTarget(BaseModel):
    """One delete/replace plan target and the blast radius computed for it."""

    model_config = ConfigDict(frozen=True)

    address: str
    tf_resource_type: str
    actions: tuple[ChangeAction, ...]
    canonical_id: str | None = None  # the stored identity it resolved to
    resolved: bool
    risk: RiskLevel | None = None  # None when the address did not resolve
    dependents: tuple[Dependent, ...] = ()
    notes: tuple[str, ...] = ()


class SimulateReport(BaseModel):
    """Blast radius of a local plan's destructive targets; nothing is applied."""

    model_config = ConfigDict(frozen=True)

    plan_path: str
    depth: int
    risk: RiskLevel  # the highest target risk (LOW when nothing was computed)
    targets: tuple[SimulatedTarget, ...] = ()
    notes: tuple[str, ...] = ()


def _missing_coverage(
    provider: str, status: dict[EvidenceSource, CoverageStatus]
) -> list[EvidenceSource]:
    """Sources that must be AVAILABLE before "no dependent" can mean LOW.

    The declared side is satisfied when either state or plan was consulted —
    each one declares every relationship Terraform knows. Any other provider
    may also carry observed and permission dependents, so those sources are
    each required individually.
    """
    missing: list[EvidenceSource] = []
    if not any(status.get(source) == CoverageStatus.AVAILABLE for source in _DECLARED_SIDE):
        missing.extend(sorted(_DECLARED_SIDE, key=lambda source: source.value))
    if provider != TERRAFORM_PROVIDER:
        missing.extend(
            source
            for source in sorted(_OBSERVED_SIDE, key=lambda source: source.value)
            if status.get(source) != CoverageStatus.AVAILABLE
        )
    return missing


class ImpactService:
    """Reverse-traverses stored relationships to a bounded depth."""

    def __init__(self, store: ScanStore) -> None:
        self._store = store

    def blast_radius(
        self,
        subject_canonical_id: str,
        *,
        depth: int = DEFAULT_DEPTH,
        basis: ImpactBasis = ImpactBasis.DISCOVERY_GRAPH,
    ) -> ImpactReport | None:
        """Compute the blast radius of one stored resource.

        Returns ``None`` when the subject has never been stored — an unknown
        resource has no honest blast radius, and guessing one is forbidden.
        """
        resource = self._store.resources.get(subject_canonical_id)
        if resource is None:
            return None
        dependents, notes = self._traverse(subject_canonical_id, depth)
        risk, coverage_notes = self._risk(resource, dependents)
        ordered = tuple(
            sorted(dependents.values(), key=lambda item: (item.depth, item.canonical_id))
        )
        return ImpactReport(
            subject_canonical_id=subject_canonical_id,
            basis=basis,
            depth=depth,
            risk=risk,
            dependents=ordered,
            notes=(*notes, *coverage_notes),
        )

    # --- traversal -------------------------------------------------------------

    def _traverse(self, subject: str, depth: int) -> tuple[dict[str, Dependent], tuple[str, ...]]:
        """Breadth-first walk against edge direction, bounded by ``depth``.

        The subject seeds the walk; every incoming edge introduces its source
        as a dependent one hop further out. The first path to a resource wins
        (breadth-first, so it is a shortest path), parallel edges from the
        same dependent are aggregated, and a revisit — including the subject
        itself, which terminates cycles — adds nothing.
        """
        dependents: dict[str, Dependent] = {}
        notes: list[str] = []
        visited = {subject}
        # (node, path from the subject, evidence of every edge group on that path)
        queue: deque[tuple[str, tuple[str, ...], tuple[tuple[Relationship, ...], ...]]] = deque(
            [(subject, (subject,), ())]
        )
        while queue:
            node, path, edge_groups = queue.popleft()
            if len(path) > depth:
                continue  # expanding this node would exceed the bound
            for source_id, edges in self._incoming_by_source(node):
                if source_id in visited:
                    continue
                visited.add(source_id)
                dependent_path = (*path, source_id)
                dependent_groups = (*edge_groups, edges)
                dependent, edge_notes = self._dependent(dependent_path, dependent_groups)
                dependents[source_id] = dependent
                notes.extend(edge_notes)
                queue.append((source_id, dependent_path, dependent_groups))
        return dependents, tuple(notes)

    def _incoming_by_source(self, node: str) -> tuple[tuple[str, tuple[Relationship, ...]], ...]:
        """Incoming edges grouped by their source, in deterministic order."""
        grouped: dict[str, list[Relationship]] = {}
        for edge in sorted(
            self._store.relationships.incoming(node),
            key=lambda item: (
                item.source_canonical_id,
                item.type.value,
                item.origin.value,
            ),
        ):
            grouped.setdefault(edge.source_canonical_id, []).append(edge)
        return tuple((source, tuple(edges)) for source, edges in grouped.items())

    def _dependent(
        self, path: tuple[str, ...], edge_groups: tuple[tuple[Relationship, ...], ...]
    ) -> tuple[Dependent, tuple[str, ...]]:
        """Build one dependent from the edge groups along its path."""
        evidence_ids: dict[str, None] = {}  # insertion-ordered dedup
        origins: set[str] = set()
        classified: list[tuple[DependentKind, Conclusion | None]] = []
        notes: list[str] = []
        for edges in edge_groups:
            for edge in edges:
                origins.add(edge.origin.value)
                for evidence_id in edge.evidence_ids:
                    evidence_ids.setdefault(evidence_id, None)
                kind, conclusion, note = self._classify(edge)
                classified.append((kind, conclusion))
                if note is not None:
                    notes.append(note)
        best: tuple[DependentKind, Conclusion | None] | None = None
        for kind, conclusion in classified:
            if best is None or _KIND_SEVERITY.index(kind) < _KIND_SEVERITY.index(best[0]):
                best = (kind, conclusion)
        kind, conclusion = best if best is not None else (DependentKind.UNKNOWN, None)
        return (
            Dependent(
                canonical_id=path[-1],
                path=path,
                depth=len(path) - 1,
                kind=kind,
                conclusion=conclusion,
                provenance=tuple(sorted(origins)),
                evidence_ids=tuple(evidence_ids),
            ),
            tuple(notes),
        )

    def _classify(self, edge: Relationship) -> tuple[DependentKind, Conclusion | None, str | None]:
        """The documentation status of one edge, from its reconciliation finding."""
        finding = self._store.findings.get(
            finding_id(edge.source_canonical_id, edge.target_canonical_id, edge.type)
        )
        if finding is None:
            return (
                DependentKind.UNKNOWN,
                None,
                f"{edge.source_canonical_id} -> {edge.target_canonical_id} "
                f"({edge.type.value}): no reconciliation finding; run reality reconcile",
            )
        if finding.conclusion is Conclusion.UNKNOWN:
            blocked = ", ".join(source.value for source in finding.unavailable_sources)
            return (
                DependentKind.UNKNOWN,
                finding.conclusion,
                f"{edge.source_canonical_id} -> {edge.target_canonical_id} "
                f"({edge.type.value}): unknown - blocked by coverage ({blocked})",
            )
        return _KIND_BY_CONCLUSION[finding.conclusion], finding.conclusion, None

    # --- risk ------------------------------------------------------------------

    def _risk(
        self, resource: Resource, dependents: dict[str, Dependent]
    ) -> tuple[RiskLevel, tuple[str, ...]]:
        if any(item.kind is DependentKind.UNDOCUMENTED for item in dependents.values()):
            return RiskLevel.HIGH, ()
        if dependents:
            return RiskLevel.MEDIUM, ()
        status: dict[EvidenceSource, CoverageStatus] = {}
        for record in self._store.coverage.all_records():
            status[record.source] = record.status  # latest record wins
        missing = _missing_coverage(resource.provider, status)
        if not missing:
            return RiskLevel.LOW, ()
        names = ", ".join(source.value for source in missing)
        return (
            RiskLevel.MEDIUM,
            (
                f"no dependent found, but coverage is unavailable or not requested "
                f"for: {names}; risk stays medium because absence of evidence is "
                "not evidence of absence",
            ),
        )


class SimulateService:
    """Computes blast radius for a local plan's delete/replace targets.

    The plan is parsed only through the Terraform adapter — a JSON reader —
    and every address is resolved through the stored address mapping (or the
    stored resource behind the address's own canonical ID) before the same
    impact traversal runs. Nothing is written, applied, proposed, or executed.
    """

    def __init__(self, store: ScanStore, *, adapter: TerraformAdapter | None = None) -> None:
        self._store = store
        self._adapter = adapter if adapter is not None else TerraformAdapter()
        self._impact = ImpactService(store)

    def run(self, plan_json: str | Path, *, depth: int = DEFAULT_DEPTH) -> SimulateReport:
        path = Path(plan_json)
        result = self._adapter.parse_file(path)
        rejection = next(
            (record for record in result.coverage if record.status == CoverageStatus.UNAVAILABLE),
            None,
        )
        if rejection is not None:
            raise ScanInputError(rejection.reason)

        targets: list[SimulatedTarget] = []
        notes: list[str] = []
        changes = [
            change
            for change in result.terraform_changes
            if any(action in _DESTRUCTIVE_ACTIONS for action in change.actions)
        ]
        if not changes:
            notes.append("the plan contains no delete or replace targets; nothing to simulate")
        for change in changes:
            targets.append(self._target(change, depth=depth))

        unresolved = [target for target in targets if not target.resolved]
        if unresolved:
            notes.append(
                f"{len(unresolved)} target(s) could not be resolved to a scanned "
                "resource; their blast radius is unknown"
            )
        return SimulateReport(
            plan_path=str(path),
            depth=depth,
            risk=self._overall(targets),
            targets=tuple(targets),
            notes=tuple(notes),
        )

    def _target(self, change: TerraformChange, *, depth: int) -> SimulatedTarget:
        canonical_id = self._resolve(change)
        if canonical_id is None:
            return SimulatedTarget(
                address=change.address,
                tf_resource_type=change.tf_resource_type,
                actions=change.actions,
                resolved=False,
                notes=(
                    f"no stored mapping and no scanned resource for '{change.address}'; "
                    "blast radius not computed",
                ),
            )
        report = self._impact.blast_radius(
            canonical_id, depth=depth, basis=ImpactBasis.TERRAFORM_PLAN
        )
        assert report is not None  # _resolve only returns scanned resources
        return SimulatedTarget(
            address=change.address,
            tf_resource_type=change.tf_resource_type,
            actions=change.actions,
            canonical_id=canonical_id,
            resolved=True,
            risk=report.risk,
            dependents=report.dependents,
            notes=report.notes,
        )

    def _resolve(self, change: TerraformChange) -> str | None:
        """The stored identity a plan address refers to, without guessing.

        A stored address mapping wins — it is the one place a resolved
        cross-world identity lives — then the address's own canonical ID when
        that resource has been scanned. Anything else is unresolved, and an
        unresolved target is reported, never guessed.
        """
        stored = self._store.terraform_addresses.get(change.address)
        candidates = (
            stored.canonical_id if stored is not None else None,
            change.canonical_id,
        )
        for candidate in candidates:
            if candidate is not None and self._store.resources.get(candidate) is not None:
                return candidate
        return None

    @staticmethod
    def _overall(targets: Sequence[SimulatedTarget]) -> RiskLevel:
        computed = [target.risk for target in targets if target.risk is not None]
        if not computed:
            return RiskLevel.LOW
        return max(computed, key=lambda risk: _RANK[risk])
