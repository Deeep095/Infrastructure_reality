"""Reports for the read-only commands: ``why``, and the rendering layer.

``WhyService`` assembles the full evidence trail of one stored resource —
the resource, its relationships, the evidence behind them, the findings
reconciliation reached, and the coverage limitations that bound what any of
it can prove. The render functions turn reports into deterministic
human-readable text, and :func:`stable_json` into byte-stable JSON: sorted
keys, no timestamps, no fabricated numbers.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence

from pydantic import BaseModel, ConfigDict

from reality.domain.enums import CoverageStatus, EvidenceSource
from reality.domain.models import Coverage, Finding, Relationship, Resource
from reality.services.impact import Dependent, ImpactReport, SimulateReport
from reality.storage.repositories import EvidenceRecord, ScanStore

#: The sources a scan can consult, in deterministic (value-sorted) order.
DISCOVERY_SOURCES: tuple[EvidenceSource, ...] = (
    EvidenceSource.AWS_RESOURCES,
    EvidenceSource.CLOUDTRAIL,
    EvidenceSource.IAM,
    EvidenceSource.TERRAFORM_PLAN,
    EvidenceSource.TERRAFORM_STATE,
)


class WhyReport(BaseModel):
    """Everything ``reality why`` can honestly say about one resource."""

    model_config = ConfigDict(frozen=True)

    resource: Resource
    outgoing: tuple[Relationship, ...] = ()
    incoming: tuple[Relationship, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()
    findings: tuple[Finding, ...] = ()
    coverage: tuple[Coverage, ...] = ()  # latest record per discovery source
    limitations: tuple[str, ...] = ()


class WhyService:
    """Explains one stored resource from the database alone."""

    def __init__(self, store: ScanStore) -> None:
        self._store = store

    def explain(self, canonical_id: str) -> WhyReport | None:
        """The resource's evidence trail, or ``None`` if it was never stored."""
        context = self._store.get_resource_context(canonical_id)
        if context is None:
            return None
        latest = self._latest_coverage()
        return WhyReport(
            resource=context.resource,
            outgoing=context.outgoing,
            incoming=context.incoming,
            evidence=context.evidence,
            findings=self._store.findings.for_subject(canonical_id),
            coverage=tuple(latest[source] for source in DISCOVERY_SOURCES if source in latest),
            limitations=tuple(self._limitations(latest)),
        )

    def _latest_coverage(self) -> dict[EvidenceSource, Coverage]:
        """The most recent coverage record per source (later records win)."""
        latest: dict[EvidenceSource, Coverage] = {}
        for record in self._store.coverage.all_records():
            latest[record.source] = record
        return latest

    @staticmethod
    def _limitations(latest: dict[EvidenceSource, Coverage]) -> Iterator[str]:
        for source in DISCOVERY_SOURCES:
            record = latest.get(source)
            if record is None:
                yield f"{source.value}: never requested - no scan has consulted this source"
            elif record.status != CoverageStatus.AVAILABLE:
                yield f"{source.value}: {record.status.value} - {record.reason}"


# --- rendering --------------------------------------------------------------------


def _render_relationship(arrow: str, relationship: Relationship) -> str:
    other = relationship.target_canonical_id if arrow == "->" else relationship.source_canonical_id
    evidence = (
        f" evidence: {', '.join(relationship.evidence_ids)}" if relationship.evidence_ids else ""
    )
    return f"    {arrow} {other} {relationship.type.value} [{relationship.origin.value}]{evidence}"


def render_why(report: WhyReport) -> str:
    resource = report.resource
    lines = [
        f"reality: why {resource.canonical_id}",
        "  resource: "
        f"{resource.resource_type.value} provider={resource.provider} "
        f"region={resource.region or '-'} account={resource.account or '-'} "
        f"name={resource.name or '-'}",
    ]
    for label, value in (
        ("native_id", resource.native_id),
        ("arn", resource.arn),
        ("terraform_address", resource.terraform_address),
    ):
        if value:
            lines.append(f"    {label}: {value}")
    lines.append(
        f"  relationships ({len(report.outgoing)} outgoing, {len(report.incoming)} incoming):"
    )
    if not report.outgoing and not report.incoming:
        lines.append("    none")
    for relationship in report.outgoing:
        lines.append(_render_relationship("->", relationship))
    for relationship in report.incoming:
        lines.append(_render_relationship("<-", relationship))
    lines.append(f"  evidence ({len(report.evidence)}):")
    if report.evidence:
        for record in report.evidence:
            evidence = record.evidence
            lines.append(
                f"    - {evidence.id}: {evidence.source.value}/{evidence.type.value} "
                f"{evidence.strength.value} - {evidence.explanation}"
            )
    else:
        lines.append("    none")
    lines.append(f"  findings ({len(report.findings)}):")
    if report.findings:
        for finding in report.findings:
            lines.append(f"    - {finding.id}: {finding.conclusion.value} - {finding.explanation}")
    else:
        lines.append("    none")
    lines.append(f"  coverage limitations ({len(report.limitations)}):")
    if report.limitations:
        lines.extend(f"    - {limitation}" for limitation in report.limitations)
    else:
        lines.append("    none; every discovery source was available")
    return "\n".join(lines) + "\n"


def _render_dependents(dependents: Sequence[Dependent], indent: str) -> list[str]:
    if not dependents:
        return [f"{indent}dependents: none"]
    lines = [f"{indent}dependents ({len(dependents)}):"]
    for dependent in dependents:
        lines.append(
            f"{indent}  - {dependent.canonical_id} "
            f"(depth {dependent.depth}, {dependent.kind.value})"
        )
        lines.append(f"{indent}      path: {' -> '.join(dependent.path)}")
        if dependent.provenance:
            lines.append(f"{indent}      provenance: {', '.join(dependent.provenance)}")
        if dependent.evidence_ids:
            lines.append(f"{indent}      evidence: {', '.join(dependent.evidence_ids)}")
    return lines


def render_impact(report: ImpactReport) -> str:
    lines = [
        f"reality: impact of {report.subject_canonical_id} "
        f"(basis {report.basis.value}, depth {report.depth})",
        f"  risk: {report.risk.value}",
    ]
    lines.extend(_render_dependents(report.dependents, "  "))
    if report.notes:
        lines.append("  notes:")
        lines.extend(f"    - {note}" for note in report.notes)
    return "\n".join(lines) + "\n"


def render_simulate(report: SimulateReport) -> str:
    lines = [
        f"reality: simulate {report.plan_path} (read-only; the plan is never applied)",
        f"  overall risk: {report.risk.value}",
        f"  targets ({len(report.targets)}):",
    ]
    if not report.targets:
        lines.append("    none")
    for target in report.targets:
        actions = ", ".join(action.value for action in target.actions)
        destination = target.canonical_id if target.resolved else "unresolved"
        lines.append(f"    - {target.address} [{actions}] -> {destination}")
        lines.append(f"        risk: {target.risk.value if target.risk is not None else 'unknown'}")
        lines.extend(_render_dependents(target.dependents, "        "))
        lines.extend(f"        note: {note}" for note in target.notes)
    if report.notes:
        lines.append("  notes:")
        lines.extend(f"    - {note}" for note in report.notes)
    return "\n".join(lines) + "\n"


def stable_json(model: BaseModel) -> str:
    """Byte-stable JSON for any report: sorted keys, no timestamps, no scores.

    Reports rendered this way are comparable across runs — the same database
    and inputs always produce the same bytes.
    """
    return json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True)
