"""Deterministic reconciliation over one selected scan snapshot.

Candidates and their evidence are never changed here: the pass reads them,
matches them, and writes its conclusions as separate :class:`Finding` rows
anchored to their own scan run. The matching rule is deliberately strict —
two candidates denote the same fact only when their canonical source,
target, and relationship type are all exactly equal, and unresolved
references never equal a resolved ID.

**The snapshot boundary.** A pass analyses exactly one scan run — the latest
non-reconciliation run by default, or an explicit ``scan_run_id``. Only
relationships with evidence linked to that run participate (evidence is the
anchor: a relationship itself carries no scan-run column), and only coverage
recorded by that run gates the conclusions. Evidence from earlier scans — a
CloudTrail event seen last week, an IAM policy read before the latest state
export — cannot influence a current pass, because it is anchored to a run
the pass does not read. Findings from any earlier pass are deleted first, so
a stale conclusion can never survive into a newer snapshot's report.

**The identity join.** Terraform declarations and AWS observations live in
different ID namespaces, so a declared triple and an observed triple about
the same real dependency would never meet by string equality. When a scan
recorded evidence-backed identity mappings (see
:mod:`reality.services.identity`), the pass groups candidates by *translated*
key — each Terraform identity replaced by the AWS identity the mapping joins
it to — and emits one finding per contributing (source, target) pair, so
both namespaces keep their own finding rather than one invented identity
replacing either. Mapping evidence joins the evidence list of any group it
translated; no mapping, no translation — a name similarity never joins
anything.

Conclusion semantics (frozen in :class:`~reality.domain.enums.Conclusion`)
and the coverage that each needs behind it:

- ``CONFIRMED``     declared (Terraform) and observed (AWS/CloudTrail) — both
                    worlds present a candidate, so no coverage question arises.
- ``UNDOCUMENTED``  observed without a declaration, while Terraform was
                    actually consulted; if it was not, the conclusion is UNKNOWN.
- ``POSSIBLE``      IAM permission with no observed usage, while CloudTrail was
                    consulted (only CloudTrail observes API usage of a
                    permission); otherwise UNKNOWN.
- ``DECLARED_ONLY`` declared without observation, while an observed source was
                    consulted; explicitly NOT evidence of inactivity.
- ``UNKNOWN``       a conclusion the stored coverage cannot support; the
                    missing sources are recorded on the finding, because
                    absence of evidence is never evidence of absence.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from reality.domain.enums import (
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    RelationshipOrigin,
    RelationshipType,
)
from reality.domain.models import Finding
from reality.services.graph import GraphView
from reality.storage.repositories import ScanStore

#: Which relationship origins count as declared / observed / permission input.
DECLARED_ORIGINS = frozenset({RelationshipOrigin.TERRAFORM_DECLARED})
OBSERVED_ORIGINS = frozenset({RelationshipOrigin.AWS_OBSERVED, RelationshipOrigin.CLOUDTRAIL})
PERMISSION_ORIGINS = frozenset({RelationshipOrigin.IAM_POLICY})

#: Which coverage sources prove a side of the comparison was consulted.
DECLARED_SOURCES = frozenset({EvidenceSource.TERRAFORM_STATE, EvidenceSource.TERRAFORM_PLAN})
OBSERVED_SOURCES = frozenset({EvidenceSource.AWS_RESOURCES, EvidenceSource.CLOUDTRAIL})

FINDING_ID_PREFIX = "reconcile"

_JOIN_NOTE = (
    "; the Terraform and AWS identities of this dependency were joined by an "
    "exact-identifier identity mapping (never a name match)"
)


def finding_id(source: str, target: str, relationship_type: RelationshipType) -> str:
    """The stable finding ID for one canonical triple.

    Format ``reconcile:{type}:{source}:{target}``. The source of a
    relationship is always a resolved resource identity and never contains
    ``:``, so the type and source are unambiguously the leading segments; a
    target may be an unresolved raw reference (an ARN pattern) that does.
    """
    return f"{FINDING_ID_PREFIX}:{relationship_type.value}:{source}:{target}"


class ReconciledRelationship(BaseModel):
    """One canonical triple and the conclusion reconciliation reached about it."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    source_canonical_id: str
    target_canonical_id: str
    relationship_type: RelationshipType
    conclusion: Conclusion
    explanation: str
    evidence_ids: tuple[str, ...] = ()
    unavailable_sources: tuple[EvidenceSource, ...] = ()


class ReconcileReport(BaseModel):
    """What one reconciliation pass concluded, plus per-conclusion counts."""

    model_config = ConfigDict(frozen=True)

    scan_run_id: int
    analysed_scan_run_id: int | None = None
    findings: tuple[ReconciledRelationship, ...] = ()
    counts: dict[str, int] = {}

    def filter_conclusion(self, conclusion: str) -> ReconcileReport:
        """Return a new report with only findings matching the given conclusion."""
        filtered = tuple(f for f in self.findings if f.conclusion.value == conclusion)
        new_counts = dict(self.counts)
        new_counts[conclusion] = len(filtered)
        for k in new_counts:
            if k != conclusion:
                new_counts[k] = 0
        return ReconcileReport(
            scan_run_id=self.scan_run_id,
            analysed_scan_run_id=self.analysed_scan_run_id,
            findings=filtered,
            counts=new_counts,
        )


class _Group:
    """Every snapshot candidate that shares one translated canonical triple.

    ``pairs`` keeps each contributing (source, target) identity pair — the
    findings are emitted per pair, never for a translated-only identity —
    and ``joined`` records whether an identity mapping translated any member
    of the group.
    """

    def __init__(self) -> None:
        self.declared: list[RelationshipOrigin] = []
        self.observed: list[RelationshipOrigin] = []
        self.permission: list[RelationshipOrigin] = []
        self.evidence_ids: dict[str, None] = {}  # insertion-ordered dedup
        self.pairs: dict[tuple[str, str], None] = {}  # insertion-ordered dedup
        self.joined = False


def _origins(origins: list[RelationshipOrigin]) -> str:
    return ", ".join(dict.fromkeys(origin.value for origin in origins))


def _coverage_by_source(store: ScanStore, scan_run_id: int) -> dict[EvidenceSource, CoverageStatus]:
    """The latest coverage status recorded within one scan run, per source.

    ``for_scan_run`` is ordered by (recorded_at, id), so within the run later
    records win — a source that was available once but failed most recently
    counts as unavailable, never the other way around.
    """
    status: dict[EvidenceSource, CoverageStatus] = {}
    for record in store.coverage.for_scan_run(scan_run_id):
        status[record.source] = record.status
    return status


def _translations(store: ScanStore, scan_run_id: int) -> dict[str, tuple[str, str]]:
    """Terraform→AWS identity translations from the snapshot's mappings.

    Returns ``terraform_id -> (aws_id, evidence_id)``. A reverse collision —
    two Terraform identities mapped onto the same AWS identity — is
    ambiguous, so both translations are dropped: translating either would
    silently merge two distinct declared resources.
    """
    claims: dict[str, list[tuple[str, str]]] = {}
    for mapping in store.identity_mappings.for_scan_run(scan_run_id):
        claims.setdefault(mapping.aws_canonical_id, []).append(
            (mapping.terraform_canonical_id, mapping.evidence_id)
        )
    return {
        terraform_id: (aws_id, evidence_id)
        for aws_id, claim_list in claims.items()
        if len(claim_list) == 1
        for terraform_id, evidence_id in claim_list
    }


def _missing_sources(
    status: dict[EvidenceSource, CoverageStatus], sources: frozenset[EvidenceSource]
) -> tuple[tuple[EvidenceSource, CoverageStatus], ...]:
    """The comparison-relevant sources that could not be consulted.

    A source with no coverage record in the analysed run counts as not
    requested.
    """
    return tuple(
        (source, status.get(source, CoverageStatus.NOT_REQUESTED))
        for source in sorted(sources, key=lambda source: source.value)
        if status.get(source) != CoverageStatus.AVAILABLE
    )


def _describe_missing(missing: tuple[tuple[EvidenceSource, CoverageStatus], ...]) -> str:
    return "; ".join(f"{source.value}: {status.value}" for source, status in missing)


def _consulted(
    status: dict[EvidenceSource, CoverageStatus], sources: frozenset[EvidenceSource]
) -> bool:
    return any(status.get(source) == CoverageStatus.AVAILABLE for source in sources)


def _classify(
    group: _Group, status: dict[EvidenceSource, CoverageStatus]
) -> tuple[Conclusion, tuple[EvidenceSource, ...], str]:
    """The conclusion for one group, the sources that blocked it, and why."""
    evidence_note = f"{len(group.evidence_ids)} evidence record(s) back it"

    if group.declared and group.observed:
        return (
            Conclusion.CONFIRMED,
            (),
            f"declared by Terraform and observed by {_origins(group.observed)}; both "
            f"worlds agree on this dependency ({evidence_note})",
        )
    if group.observed:
        missing = _missing_sources(status, DECLARED_SOURCES)
        if _consulted(status, DECLARED_SOURCES):
            return (
                Conclusion.UNDOCUMENTED,
                (),
                f"observed by {_origins(group.observed)} with no matching Terraform "
                "declaration; Terraform was consulted, so the declared counterpart is "
                f"missing rather than unread ({evidence_note})",
            )
        return (
            Conclusion.UNKNOWN,
            tuple(source for source, _ in missing),
            f"observed by {_origins(group.observed)}, but whether it is declared could "
            f"not be determined: {_describe_missing(missing)}",
        )
    if group.declared:
        missing = _missing_sources(status, OBSERVED_SOURCES)
        if _consulted(status, OBSERVED_SOURCES):
            return (
                Conclusion.DECLARED_ONLY,
                (),
                "declared by Terraform but not observed by any consulted source; "
                "DECLARED_ONLY is not evidence that the dependency is inactive "
                f"({evidence_note})",
            )
        return (
            Conclusion.UNKNOWN,
            tuple(source for source, _ in missing),
            "declared by Terraform, but whether it is observed could not be "
            f"determined: {_describe_missing(missing)}",
        )
    # Permission-only: usage of an IAM permission would be observed by
    # CloudTrail data events, which LookupEvents does not expose, so this is
    # never more than POSSIBLE.
    return (
        Conclusion.POSSIBLE,
        (),
        "an IAM policy grants this permission and no usage was observed; data-plane "
        "usage is not visible to this scan, so this is a possibility, not a "
        f"confirmed dependency ({evidence_note})",
    )


class ReconcileService:
    """Matches one snapshot's candidates and writes separate findings.

    Everything the pass reads is untouched; it writes findings (and the scan
    run they anchor to) and nothing else. Deterministic: the same stored
    candidates and coverage always produce the same findings, in the same
    order, with the same IDs.
    """

    def __init__(self, store: ScanStore) -> None:
        self._store = store

    def run(self, scan_run_id: int | None = None) -> ReconcileReport:
        snapshot = self._snapshot(scan_run_id)
        graph = GraphView(self._store, snapshot)
        status = _coverage_by_source(self._store, snapshot)
        groups = self._group(graph)
        items: list[ReconciledRelationship] = []
        for source, target, rel_type in sorted(
            groups, key=lambda key: (key[0], key[1], key[2].value)
        ):
            group = groups[(source, target, rel_type)]
            if not (group.declared or group.observed or group.permission):
                continue  # e.g. simulation-only candidates are not an input here
            conclusion, unavailable, explanation = _classify(group, status)
            if group.joined:
                explanation += _JOIN_NOTE
            # One finding per contributing identity pair: a translated group
            # still reports in each namespace that actually carried evidence.
            for pair_source, pair_target in group.pairs:
                items.append(
                    ReconciledRelationship(
                        finding_id=finding_id(pair_source, pair_target, rel_type),
                        source_canonical_id=pair_source,
                        target_canonical_id=pair_target,
                        relationship_type=rel_type,
                        conclusion=conclusion,
                        explanation=explanation,
                        evidence_ids=tuple(group.evidence_ids),
                        unavailable_sources=unavailable,
                    )
                )

        counts = {conclusion.value: 0 for conclusion in Conclusion}
        for item in items:
            counts[item.conclusion.value] += 1

        with self._store.scan(source=EvidenceSource.RECONCILIATION) as session:
            run_id = session.scan_run_id
            for item in items:
                session.upsert_finding(
                    Finding(
                        id=item.finding_id,
                        subject_canonical_id=item.source_canonical_id,
                        conclusion=item.conclusion,
                        explanation=item.explanation,
                        evidence_ids=item.evidence_ids,
                        unavailable_sources=item.unavailable_sources,
                    )
                )
            # Conclusions from an earlier pass belong to that pass's snapshot;
            # anything this pass no longer concludes must not survive it.
            session.delete_stale_findings({item.finding_id for item in items})

        return ReconcileReport(
            scan_run_id=run_id,
            analysed_scan_run_id=snapshot,
            findings=tuple(items),
            counts=counts,
        )

    # --- snapshot selection ----------------------------------------------------

    def _snapshot(self, scan_run_id: int | None) -> int:
        """The scan run this pass analyses.

        An explicit ``scan_run_id`` must identify a stored discovery run — a
        missing run or a reconciliation run raises, because reconciling a
        reconciliation would read its pass findings as evidence. The default
        is the latest discovery run; with no discovery runs at all there is
        nothing to analyse.
        """
        if scan_run_id is not None:
            source = self._store.scan_runs.get_source(scan_run_id)
            if source is None:
                raise ValueError(f"scan run {scan_run_id} does not exist")
            if source == EvidenceSource.RECONCILIATION:
                raise ValueError(
                    f"scan run {scan_run_id} is a reconciliation pass, not a scan; "
                    "analyse a discovery run instead"
                )
            return scan_run_id
        latest = self._store.scan_runs.latest_discovery_run()
        if latest is None:
            raise ValueError("no discovery scan to analyse: run a scan first")
        return latest

    # --- grouping ----------------------------------------------------------------

    def _group(self, graph: GraphView) -> dict[tuple[str, str, RelationshipType], _Group]:
        """Group the snapshot's candidates by their translated canonical triple.

        A Terraform identity with a snapshot identity mapping translates to
        the AWS identity it was joined to; anything else (including every AWS
        and unresolved identity) translates to itself, so unmapped declared
        candidates group only with exact string-equal counterparts, as before.
        """
        translations = _translations(self._store, graph.scan_run_id)
        groups: dict[tuple[str, str, RelationshipType], _Group] = {}
        for relationship in graph.outgoing_all():
            translated_source, source_evidence = self._translate(
                relationship.source_canonical_id, translations
            )
            translated_target, target_evidence = self._translate(
                relationship.target_canonical_id, translations
            )
            key = (translated_source, translated_target, relationship.type)
            group = groups.setdefault(key, _Group())
            group.pairs.setdefault(
                (relationship.source_canonical_id, relationship.target_canonical_id), None
            )
            for evidence_id in relationship.evidence_ids:
                group.evidence_ids.setdefault(evidence_id, None)
            for mapped_evidence in (source_evidence, target_evidence):
                if mapped_evidence is not None:
                    group.evidence_ids.setdefault(mapped_evidence, None)
                    group.joined = True
            if relationship.origin in DECLARED_ORIGINS:
                group.declared.append(relationship.origin)
            elif relationship.origin in OBSERVED_ORIGINS:
                group.observed.append(relationship.origin)
            elif relationship.origin in PERMISSION_ORIGINS:
                group.permission.append(relationship.origin)
        return groups

    @staticmethod
    def _translate(
        canonical_id: str, translations: dict[str, tuple[str, str]]
    ) -> tuple[str, str | None]:
        """One identity through the snapshot's mappings: translated key and
        the mapping's evidence ID when a translation fired."""
        mapped = translations.get(canonical_id)
        if mapped is None:
            return canonical_id, None
        return mapped[0], mapped[1]
