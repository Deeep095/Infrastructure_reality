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

The outcome is a :class:`Verdict` about what the evidence supports, plus a
plain count of what was found. There is deliberately no severity band: see
:class:`Verdict`.
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
    RelationshipOrigin,
    _StrEnum,
)
from reality.domain.ids import TERRAFORM_PROVIDER
from reality.domain.models import Relationship, Resource, TerraformChange
from reality.services.graph import IdentityResolver
from reality.services.reconcile import finding_id
from reality.services.scan import ScanInputError
from reality.storage.repositories import ScanStore

#: The traversal bound when the caller does not choose one.
DEFAULT_DEPTH = 3

#: Sources that can store relationships targeting a Terraform-namespace
#: subject (only the declared world ever targets those canonical IDs).
_DECLARED_SIDE = frozenset({EvidenceSource.TERRAFORM_STATE, EvidenceSource.TERRAFORM_PLAN})

#: Sources that can reveal operational dependents of a non-Terraform subject.
#: IAM policy grants are authorization candidates, not runtime dependencies.
_OBSERVED_SIDE = frozenset({EvidenceSource.AWS_RESOURCES, EvidenceSource.CLOUDTRAIL})

#: Simulate acts on destructive-looking actions only; an update is not a
#: removal, and this classifier never applies anything regardless.
_DESTRUCTIVE_ACTIONS = frozenset({ChangeAction.DELETE, ChangeAction.REPLACE})


class Verdict(StrEnum):
    """What the stored evidence supports about one blast radius.

    Deliberately not a severity band. A severity would have to weigh how much
    the affected resources matter, and this tool has no way to know that — it
    knows which edges exist, which sources it managed to consult, and what
    reconciliation concluded. Scoring that as HIGH/MEDIUM/LOW was the one
    fabricated judgement in a code base whose whole premise is that evidence is
    not a conclusion, so it is gone.

    Each value names a different next action instead:

    - ``UNDOCUMENTED_DEPENDENTS`` something depends on this subject that no
      declaration accounts for. Look at it before touching the subject.
    - ``INCONCLUSIVE`` the question could not be answered: a dependent's
      conclusion was blocked by missing coverage or was never reconciled, or
      nothing was found while a source that could have revealed a dependent
      went unconsulted. Widen the scan; do not read this as "safe".
    - ``DEPENDENTS_DOCUMENTED`` dependents exist and every one is accounted
      for. Read the list.
    - ``NO_DEPENDENTS_FOUND`` nothing depends on this subject, and every
      source that could have shown otherwise was actually consulted.

    How many dependents there are is reported separately as a count, because a
    count is a fact and a band is an opinion.
    """

    UNDOCUMENTED_DEPENDENTS = "undocumented_dependents"
    INCONCLUSIVE = "inconclusive"
    DEPENDENTS_DOCUMENTED = "dependents_documented"
    NO_DEPENDENTS_FOUND = "no_dependents_found"


#: A one-line statement of the rule behind each verdict, so a report explains
#: itself without the reader opening this module.
VERDICT_GLOSS: dict[Verdict, str] = {
    Verdict.UNDOCUMENTED_DEPENDENTS: "at least one dependent has no declaration",
    Verdict.INCONCLUSIVE: "a dependent or a source could not be decided on",
    Verdict.DEPENDENTS_DOCUMENTED: "every dependent found is accounted for",
    Verdict.NO_DEPENDENTS_FOUND: "no dependents, and every relevant source was consulted",
}


class DependentKind(StrEnum):
    """How well-documented one dependent's dependency is."""

    DOCUMENTED = "documented"  # declared in Terraform (CONFIRMED or DECLARED_ONLY)
    UNDOCUMENTED = "undocumented"  # observed with no declaration
    POSSIBLE = "possible"  # IAM permission, no observed usage
    UNKNOWN = "unknown"  # conclusion blocked by coverage, or never reconciled


class DependentCounts(BaseModel):
    """How many dependents were found, broken down by how well documented.

    The honest replacement for a severity band: the reader decides what twelve
    documented dependents means for their system, which is a judgement this
    tool is not in a position to make for them.
    """

    model_config = ConfigDict(frozen=True)

    total: int = 0
    documented: int = 0
    undocumented: int = 0
    possible: int = 0
    unknown: int = 0

    @classmethod
    def of(cls, dependents: Sequence[Dependent]) -> DependentCounts:
        kinds = [dependent.kind for dependent in dependents]
        return cls(
            total=len(kinds),
            documented=kinds.count(DependentKind.DOCUMENTED),
            undocumented=kinds.count(DependentKind.UNDOCUMENTED),
            possible=kinds.count(DependentKind.POSSIBLE),
            unknown=kinds.count(DependentKind.UNKNOWN),
        )

    def summary(self) -> str:
        """A one-line breakdown, naming only the kinds actually present."""
        parts = [
            f"{count} {label}"
            for label, count in (
                ("documented", self.documented),
                ("undocumented", self.undocumented),
                ("possible", self.possible),
                ("unknown", self.unknown),
            )
            if count
        ]
        return f"{self.total} ({', '.join(parts)})" if parts else "0"


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

#: Verdicts ordered least to most cautionary. Used to pick the overall verdict
#: for a plan with several targets, and to order the ``--fail-on`` thresholds.
_VERDICT_RANK: dict[Verdict, int] = {
    Verdict.NO_DEPENDENTS_FOUND: 0,
    Verdict.DEPENDENTS_DOCUMENTED: 1,
    Verdict.INCONCLUSIVE: 2,
    Verdict.UNDOCUMENTED_DEPENDENTS: 3,
}


def verdict_rank(verdict: Verdict) -> int:
    """How cautionary a verdict is, for threshold comparisons."""
    return _VERDICT_RANK[verdict]


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
    """The blast radius of one subject: dependents, verdict, and caveats."""

    model_config = ConfigDict(frozen=True)

    subject_canonical_id: str
    basis: ImpactBasis
    depth: int
    verdict: Verdict
    counts: DependentCounts = DependentCounts()
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
    verdict: Verdict | None = None  # None when the address did not resolve
    counts: DependentCounts = DependentCounts()
    dependents: tuple[Dependent, ...] = ()
    notes: tuple[str, ...] = ()


class Assessment(_StrEnum):
    """Whether every destructive target could be assessed.

    Distinct from :class:`Verdict`: a plan whose targets are all unresolved has
    no verdict to report, which is not the same as a reassuring one.
    """

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    NOT_APPLICABLE = "not_applicable"


class SimulateReport(BaseModel):
    """Blast radius of a local plan's destructive targets; nothing is applied."""

    model_config = ConfigDict(frozen=True)

    plan_path: str
    depth: int
    verdict: Verdict | None  # None when no target could be assessed
    assessment: Assessment
    counts: DependentCounts = DependentCounts()
    targets: tuple[SimulatedTarget, ...] = ()
    notes: tuple[str, ...] = ()


def _missing_coverage(
    provider: str, status: dict[EvidenceSource, CoverageStatus]
) -> list[EvidenceSource]:
    """Sources that must be AVAILABLE before "no dependent" can be conclusive.

    The declared side is satisfied when either state or plan was consulted —
    each one declares every relationship Terraform knows. Other providers may
    have operational dependents visible through AWS resources or CloudTrail;
    IAM policy grants are excluded because permission does not prove runtime use.
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
        self._resolver = IdentityResolver(store.resources.all(), store.relationships.all())

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
        resolved = self._resolve_subject(subject_canonical_id)
        if resolved is None:
            return None
        resource = self._store.resources.get(resolved)
        if resource is None:
            return None
        dependents, notes = self._traverse(resolved, depth)
        verdict, verdict_notes = self._verdict(resource, dependents)
        ordered = tuple(
            sorted(dependents.values(), key=lambda item: (item.depth, item.canonical_id))
        )
        return ImpactReport(
            subject_canonical_id=resolved,
            basis=basis,
            depth=depth,
            verdict=verdict,
            counts=DependentCounts.of(ordered),
            dependents=ordered,
            notes=(*notes, *verdict_notes),
        )

    # --- traversal -------------------------------------------------------------

    def _resolve_subject(self, subject_canonical_id: str) -> str | None:
        """The stored ID to report on, or ``None`` if the subject is unknown.

        Resolves through compatible identities so a less-qualified reference
        (an accountless S3 bucket ARN) reaches the stored, account-qualified
        resource. The first stored match wins; an unresolvable subject stays
        unknown rather than being guessed at.
        """
        for stored_id in self._resolver.resolve(subject_canonical_id):
            if self._resolver.is_stored(stored_id):
                return stored_id
        return None

    def _traverse(self, subject: str, depth: int) -> tuple[dict[str, Dependent], tuple[str, ...]]:
        """Breadth-first walk against edge direction, bounded by ``depth``.

        The subject seeds the walk; every incoming non-IAM-policy edge introduces
        its source as a dependent one hop further out. The first path to a resource wins
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
            incoming, excluded_permissions = self._incoming_by_source(node)
            permission_note = (
                "IAM policy grants are excluded from impact dependents: an allowed action "
                "does not prove the resource is used at runtime. Review reconcile findings "
                "for possible permissions."
            )
            if excluded_permissions and permission_note not in notes:
                notes.append(permission_note)
            for source_id, edges in incoming:
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

    def _incoming_by_source(
        self, node: str
    ) -> tuple[tuple[tuple[str, tuple[Relationship, ...]], ...], bool]:
        """Incoming edges grouped by their source, in deterministic order.

        The node is resolved through every stored identity that denotes the
        same resource, so an edge recorded against a less-qualified endpoint
        (an accountless S3 bucket ARN) still reaches the stored bucket. IAM
        policy grants are omitted because authorization alone is not runtime use.
        """
        grouped: dict[str, list[Relationship]] = {}
        excluded_permissions = False
        for edge in self._resolver.incoming(node):
            if edge.origin is RelationshipOrigin.IAM_POLICY:
                excluded_permissions = True
                continue
            grouped.setdefault(edge.source_canonical_id, []).append(edge)
        ordered = sorted(
            grouped.items(),
            key=lambda item: (
                item[0],
                min(edge.type.value for edge in item[1]),
                min(edge.origin.value for edge in item[1]),
            ),
        )
        return tuple((source, tuple(edges)) for source, edges in ordered), excluded_permissions

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

    # --- verdict ---------------------------------------------------------------

    def _verdict(
        self, resource: Resource, dependents: dict[str, Dependent]
    ) -> tuple[Verdict, tuple[str, ...]]:
        """What the evidence supports about this subject's blast radius.

        Precedence runs from the most cautionary down: proven drift first, then
        any gap that stops the question being answered, then a complete answer.
        Both UNKNOWN and POSSIBLE dependents count as gaps — one has no usable
        conclusion, the other is a permission nobody was observed using, and
        neither is something the declared world can be said to account for. The
        retired risk band lumped both in with documented dependents under
        MEDIUM and lost that distinction.
        """
        kinds = {dependent.kind for dependent in dependents.values()}
        if DependentKind.UNDOCUMENTED in kinds:
            return Verdict.UNDOCUMENTED_DEPENDENTS, ()
        if DependentKind.UNKNOWN in kinds:
            return (
                Verdict.INCONCLUSIVE,
                (
                    "at least one dependent has no usable conclusion, so whether the "
                    "declared world accounts for this blast radius is undecided; run "
                    "reality reconcile, or widen the scan's coverage",
                ),
            )
        if DependentKind.POSSIBLE in kinds:
            return (
                Verdict.INCONCLUSIVE,
                (
                    "at least one dependent rests on a permission with no observed "
                    "usage behind it, which is a possibility rather than a dependency",
                ),
            )
        if dependents:
            return Verdict.DEPENDENTS_DOCUMENTED, ()

        status: dict[EvidenceSource, CoverageStatus] = {}
        for record in self._store.coverage.all_records():
            status[record.source] = record.status  # latest record wins
        missing = _missing_coverage(resource.provider, status)
        if not missing:
            return Verdict.NO_DEPENDENTS_FOUND, ()
        names = ", ".join(source.value for source in missing)
        return (
            Verdict.INCONCLUSIVE,
            (
                f"no dependent was found, but coverage is unavailable or was not "
                f"requested for: {names}; absence of evidence is not evidence of "
                "absence, so this is undecided rather than clear",
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
            verdict=self._overall(targets),
            assessment=self._assessment(targets),
            counts=DependentCounts.of(
                [dependent for target in targets for dependent in target.dependents]
            ),
            targets=tuple(targets),
            notes=tuple(notes),
        )

    @staticmethod
    def _assessment(targets: Sequence[SimulatedTarget]) -> Assessment:
        """Whether every destructive target could be assessed.

        A plan with no destructive targets is not applicable. A plan where any
        target is unresolved is incomplete — the targets that did resolve may
        look clear, but the assessment did not cover everything it was asked
        about.
        """
        if not targets:
            return Assessment.NOT_APPLICABLE
        if any(not target.resolved for target in targets):
            return Assessment.INCOMPLETE
        return Assessment.COMPLETE

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
            verdict=report.verdict,
            counts=report.counts,
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
    def _overall(targets: Sequence[SimulatedTarget]) -> Verdict | None:
        """The most cautionary verdict among the targets that could be assessed.

        ``None`` when no target resolved — there is nothing to report a verdict
        about, which is not the same as a reassuring one.
        """
        computed = [target.verdict for target in targets if target.verdict is not None]
        if not computed:
            return None
        return max(computed, key=verdict_rank)
