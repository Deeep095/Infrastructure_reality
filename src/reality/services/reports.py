"""Reports for the read-only commands: ``why``, and the rendering layer.

``WhyService`` assembles the full evidence trail of one stored resource —
the resource, its relationships, the evidence behind them, the findings
reconciliation reached, and the coverage limitations that bound what any of
it can prove. The render functions turn reports into deterministic
human-readable text, and :func:`stable_json` into byte-stable JSON: sorted
keys, no timestamps, no fabricated numbers.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from reality.domain.enums import Conclusion, CoverageStatus, EvidenceSource
from reality.domain.ids import parse_canonical
from reality.domain.models import Coverage, Finding, Relationship, Resource
from reality.services.impact import Dependent, ImpactReport, SimulateReport
from reality.services.reconcile import ReconciledRelationship, ReconcileReport
from reality.storage.repositories import EvidenceRecord, ScanStore

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

#: The sources a scan can consult, in deterministic (value-sorted) order.
DISCOVERY_SOURCES: tuple[EvidenceSource, ...] = (
    EvidenceSource.AWS_RESOURCES,
    EvidenceSource.CLOUDTRAIL,
    EvidenceSource.IAM,
    EvidenceSource.TERRAFORM_PLAN,
    EvidenceSource.TERRAFORM_STATE,
)

#: Message shown when ``--output table`` is asked for without rich installed.
TABLE_EXTRA_HINT = (
    "the 'table' output format needs the optional 'rich' package; "
    "install it with: pip install 'Infrastructure_reality[table]' "
    "(or use --output text/json/yaml/csv, which have no extra dependency)"
)


class MissingTableExtra(ImportError):
    """``--output table`` was requested but rich is not installed.

    A distinct exception type so the CLI can report the fix and exit with a
    usage error, instead of surfacing a bare ``ModuleNotFoundError`` from deep
    inside an import chain.
    """


def _rich() -> tuple[type[Console], type[Table], type[Text]]:
    """Import rich on demand, or explain how to get it.

    rich is an optional display dependency, imported here rather than at module
    scope so that ``text``, ``json``, ``yaml`` and ``csv`` output — and every
    command that merely imports this module — work without it. This mirrors how
    boto3 is confined to the AWS adapters.
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise MissingTableExtra(TABLE_EXTRA_HINT) from exc
    return Console, Table, Text


def _short_id(canonical_id: str) -> str:
    """Return a short display form of a canonical ID."""
    try:
        cid = parse_canonical(canonical_id)
        return cid.short_id()
    except Exception:
        return canonical_id


def _short_ids_in_text(text: str) -> str:
    """Replace canonical IDs in text with their short forms."""
    # Match canonical ID pattern: provider/service/type/region/account/id
    import re

    pattern = r"(\w+/\w+/\w+/[^/]+/[^/]+/\S+)"

    def replace_id(match: re.Match[str]) -> str:
        return _short_id(match.group(1))

    return re.sub(pattern, replace_id, text)


def _path_display(path: Sequence[str]) -> str:
    """Render a traversal path in the direction the edges actually point.

    ``Dependent.path`` is stored subject-first, because that is the order the
    breadth-first walk visited the nodes in. Every edge along it, though, runs
    from the dependent *into* the subject, so printing the tuple as stored
    would show the chain pointing the wrong way. Reversing it makes the
    printed path agree with the relationships it came from.
    """
    return " -> ".join(reversed(path))


def _short_path_display(path: Sequence[str]) -> str:
    """The same path, in short display form, for the table renderer."""
    return " -> ".join(_short_id(node) for node in reversed(path))


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


def _conclusion_counts(report: ReconcileReport) -> str:
    """Per-conclusion counts in reading order, omitting conclusions with none."""
    present = [item.conclusion for item in report.findings]
    parts = [
        f"{conclusion.value} {present.count(conclusion)}"
        for conclusion in CONCLUSION_ORDER
        if present.count(conclusion)
    ]
    return ", ".join(parts)


def render_reconcile(report: ReconcileReport) -> str:
    analysed = (
        f"analysing scan run {report.analysed_scan_run_id}"
        if report.analysed_scan_run_id is not None
        else "no snapshot analysed"
    )
    lines = [
        f"reality: reconcile pass {report.scan_run_id} ({analysed})",
        f"  findings ({len(report.findings)}): {_conclusion_counts(report) or 'none'}",
    ]
    by_conclusion: dict[Conclusion, list[ReconciledRelationship]] = {}
    for item in report.findings:
        by_conclusion.setdefault(item.conclusion, []).append(item)
    for conclusion in CONCLUSION_ORDER:
        items = by_conclusion.get(conclusion)
        if not items:
            continue
        lines.append(f"  {conclusion.value} ({len(items)}) - {CONCLUSION_GLOSS[conclusion]}:")
        for item in items:
            lines.append(
                f"    - {item.source_canonical_id} -> {item.target_canonical_id} "
                f"[{item.relationship_type.value}]"
            )
            lines.append(f"        {item.explanation}")
            if item.evidence_ids:
                lines.append(f"        evidence: {', '.join(item.evidence_ids)}")
            if item.unavailable_sources:
                missing = ", ".join(source.value for source in item.unavailable_sources)
                lines.append(f"        missing coverage: {missing}")
    if not report.findings:
        lines.append("    none; the snapshot held no relationship candidates to compare")
    return "\n".join(lines) + "\n"


# --- rich table rendering ---------------------------------------------------------


def _risk_style(risk_value: str) -> str:
    """Return rich style for risk level."""
    styles = {
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold green",
        "unknown": "dim",
    }
    return styles.get(risk_value.lower(), "")


def _strength_style(strength: str) -> str:
    """Return rich style for evidence strength."""
    styles = {
        "high": "green",
        "medium": "yellow",
        "low": "red",
    }
    return styles.get(strength.lower(), "")


def _coverage_style(status: CoverageStatus) -> str:
    """Return rich style for coverage status."""
    styles = {
        CoverageStatus.AVAILABLE: "green",
        CoverageStatus.UNAVAILABLE: "red",
        CoverageStatus.NOT_REQUESTED: "yellow",
    }
    return styles.get(status, "")


def _kind_style(kind: str) -> str:
    """Return rich style for dependent kind."""
    styles = {
        "direct": "cyan",
        "transitive": "blue",
        "unknown": "dim",
    }
    return styles.get(kind.lower(), "")


def _conclusion_style(conclusion: str) -> str:
    """Return rich style for a reconciliation conclusion."""
    styles = {
        Conclusion.UNDOCUMENTED.value: "bold red",
        Conclusion.DECLARED_ONLY.value: "yellow",
        Conclusion.POSSIBLE.value: "yellow",
        Conclusion.UNKNOWN.value: "dim",
        Conclusion.CONFIRMED.value: "green",
    }
    return styles.get(conclusion.lower(), "")


#: Conclusions in the order a reviewer should read them: the ones that can
#: change a decision first, the reassuring ones last.
CONCLUSION_ORDER: tuple[Conclusion, ...] = (
    Conclusion.UNDOCUMENTED,
    Conclusion.DECLARED_ONLY,
    Conclusion.POSSIBLE,
    Conclusion.UNKNOWN,
    Conclusion.CONFIRMED,
)

#: A one-line gloss per conclusion, so the text report explains itself.
CONCLUSION_GLOSS: dict[Conclusion, str] = {
    Conclusion.UNDOCUMENTED: "observed in the cloud, but no declaration accounts for it",
    Conclusion.DECLARED_ONLY: "declared, but not observed; not evidence the resource is unused",
    Conclusion.POSSIBLE: "an IAM policy allows it, but no usage was observed",
    Conclusion.UNKNOWN: "the coverage needed to decide was missing",
    Conclusion.CONFIRMED: "declared and observed on the same triple",
}


def render_why_table(report: WhyReport) -> None:
    Console, Table, Text = _rich()
    resource = report.resource
    console = Console(force_terminal=True, legacy_windows=True, width=120)

    # Resource info table
    title = f"[bold cyan]reality: why {_short_id(resource.canonical_id)}[/bold cyan]"
    resource_table = Table(title=title, show_header=False, box=None, padding=(0, 2))
    resource_table.add_column("Field", style="bold")
    resource_table.add_column("Value")

    resource_table.add_row("Type", f"{resource.resource_type.value}")
    resource_table.add_row("Provider", resource.provider)
    resource_table.add_row("Region", resource.region or "-")
    resource_table.add_row("Account", resource.account or "-")
    resource_table.add_row("Name", resource.name or "-")
    if resource.native_id:
        resource_table.add_row("Native ID", resource.native_id)
    if resource.arn:
        resource_table.add_row("ARN", resource.arn)
    if resource.terraform_address:
        resource_table.add_row("Terraform Address", resource.terraform_address)

    console.print(resource_table)

    # Relationships table
    if report.outgoing or report.incoming:
        rel_table = Table(
            title="[bold]Relationships[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        rel_table.add_column("Direction", style="bold")
        rel_table.add_column("Target Resource", overflow="fold")
        rel_table.add_column("Type")
        rel_table.add_column("Origin")
        rel_table.add_column("Evidence", overflow="fold")

        for rel in report.outgoing:
            evidence = ", ".join(rel.evidence_ids) if rel.evidence_ids else "-"
            rel_table.add_row(
                "->", _short_id(rel.target_canonical_id), rel.type.value, rel.origin.value, evidence
            )
        for rel in report.incoming:
            evidence = ", ".join(rel.evidence_ids) if rel.evidence_ids else "-"
            rel_table.add_row(
                "<-", _short_id(rel.source_canonical_id), rel.type.value, rel.origin.value, evidence
            )

        console.print(rel_table)
    else:
        console.print("[dim]Relationships: none[/dim]")

    # Evidence table
    if report.evidence:
        ev_table = Table(
            title="[bold]Evidence[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        ev_table.add_column("ID", overflow="fold")
        ev_table.add_column("Source", overflow="fold")
        ev_table.add_column("Type")
        ev_table.add_column("Strength", justify="center")
        ev_table.add_column("Explanation", overflow="fold")

        for record in report.evidence:
            ev = record.evidence
            strength_text = Text(ev.strength.value, style=_strength_style(ev.strength.value))
            ev_table.add_row(ev.id, ev.source.value, ev.type.value, strength_text, ev.explanation)

        console.print(ev_table)
    else:
        console.print("[dim]Evidence: none[/dim]")

    # Findings table
    if report.findings:
        find_table = Table(
            title="[bold]Findings[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        find_table.add_column("ID", overflow="fold")
        find_table.add_column("Conclusion", justify="center")
        find_table.add_column("Explanation", overflow="fold")

        for finding in report.findings:
            conclusion_text = Text(
                finding.conclusion.value, style=_risk_style(finding.conclusion.value)
            )
            find_table.add_row(finding.id, conclusion_text, finding.explanation)

        console.print(find_table)
    else:
        console.print("[dim]Findings: none[/dim]")

    # Coverage limitations table
    if report.limitations:
        cov_table = Table(
            title="[bold]Coverage Limitations[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        cov_table.add_column("Source")
        cov_table.add_column("Status", justify="center")
        cov_table.add_column("Reason", overflow="fold")

        for limitation in report.limitations:
            parts = limitation.split(" - ", 1)
            source = parts[0] if len(parts) > 1 else limitation
            status_reason = parts[1] if len(parts) > 1 else ""
            status_parts = (
                status_reason.split(" - ", 1) if " - " in status_reason else [status_reason, ""]
            )
            status = status_parts[0]
            reason = status_parts[1] if len(status_parts) > 1 else ""
            valid_status = status in [s.value for s in CoverageStatus]
            coverage_status = CoverageStatus(status) if valid_status else None
            style = _coverage_style(coverage_status) if coverage_status else ""
            status_text = Text(status, style=style)
            cov_table.add_row(source, status_text, reason)

        console.print(cov_table)
    else:
        console.print("[green]Coverage: all discovery sources available[/green]")


def _render_dependents_table(
    dependents: Sequence[Dependent], console: Console, indent: str = ""
) -> None:
    _, Table, Text = _rich()
    if not dependents:
        console.print(f"{indent}[dim]Dependents: none[/dim]")
        return

    dep_table = Table(
        title=f"[bold]Dependents ({len(dependents)})[/bold]",
        show_header=True,
        header_style="bold cyan",
    )
    dep_table.add_column("Resource", overflow="fold")
    dep_table.add_column("Depth", justify="center")
    dep_table.add_column("Kind", justify="center")
    dep_table.add_column("Path", overflow="fold")
    dep_table.add_column("Provenance", overflow="fold")
    dep_table.add_column("Evidence", overflow="fold")

    for dep in dependents:
        kind_text = Text(dep.kind.value, style=_kind_style(dep.kind.value))
        path_str = _short_path_display(dep.path) if dep.path else "-"
        provenance_str = ", ".join(dep.provenance) if dep.provenance else "-"
        evidence_str = ", ".join(dep.evidence_ids) if dep.evidence_ids else "-"
        resource_short = _short_id(dep.canonical_id)
        depth_str = str(dep.depth)
        dep_table.add_row(
            resource_short, depth_str, kind_text, path_str, provenance_str, evidence_str
        )

    console.print(dep_table)


def render_impact_table(report: ImpactReport) -> None:
    Console, _, Text = _rich()
    console = Console(force_terminal=True, legacy_windows=True, width=140)

    # Header
    risk_text = Text(report.risk.value.upper(), style=_risk_style(report.risk.value))
    subject_short = _short_id(report.subject_canonical_id)
    console.print(f"[bold cyan]reality: impact of {subject_short}[/bold cyan]")
    basis_line = (
        f"  Basis: [bold]{report.basis.value}[/bold] | "
        f"Depth: [bold]{report.depth}[/bold] | Risk: {risk_text}"
    )
    console.print(basis_line)

    _render_dependents_table(report.dependents, console, "  ")

    if report.notes:
        console.print("\n[bold]Notes:[/bold]")
        for note in report.notes:
            console.print(f"  - {_short_ids_in_text(note)}")


def render_simulate_table(report: SimulateReport) -> None:
    Console, _, Text = _rich()
    console = Console(force_terminal=True, legacy_windows=True, width=140)

    # Header
    overall_risk_text = Text(report.risk.value.upper(), style=_risk_style(report.risk.value))
    console.print(f"[bold cyan]reality: simulate {report.plan_path}[/bold cyan]")
    console.print("  [dim]read-only; the plan is never applied[/dim]")
    console.print(f"  Overall Risk: {overall_risk_text}")
    console.print(f"  Targets: {len(report.targets)}")

    if not report.targets:
        console.print("[dim]  No targets in plan[/dim]")
    else:
        for i, target in enumerate(report.targets):
            actions = ", ".join(action.value for action in target.actions)
            canonical = target.canonical_id if target.resolved and target.canonical_id else None
            dest = _short_id(canonical) if canonical else "[red]unresolved[/red]"
            target_risk = target.risk.value if target.risk is not None else "unknown"
            risk_text = Text(target_risk.upper(), style=_risk_style(target_risk))

            console.print(
                f"\n  [bold]Target {i + 1}:[/bold] {target.address} [{actions}] -> {dest}"
            )
            console.print(f"    Risk: {risk_text}")

            _render_dependents_table(target.dependents, console, "    ")

            if target.notes:
                for note in target.notes:
                    console.print(f"    Note: {_short_ids_in_text(note)}")

    if report.notes:
        console.print("\n[bold]Notes:[/bold]")
        for note in report.notes:
            console.print(f"  - {_short_ids_in_text(note)}")


def render_reconcile_table(report: ReconcileReport) -> None:
    Console, Table, Text = _rich()
    console = Console(force_terminal=True, legacy_windows=True, width=140)

    analysed = (
        f"analysing scan run {report.analysed_scan_run_id}"
        if report.analysed_scan_run_id is not None
        else "no snapshot analysed"
    )
    console.print(f"[bold cyan]reality: reconcile pass {report.scan_run_id}[/bold cyan]")
    console.print(f"  [dim]{analysed}[/dim]")
    console.print(f"  Findings: [bold]{len(report.findings)}[/bold]")

    if not report.findings:
        console.print("[dim]  No relationship candidates to compare in this snapshot[/dim]")
        return

    counts_table = Table(
        title="[bold]Findings by conclusion[/bold]",
        show_header=True,
        header_style="bold cyan",
    )
    counts_table.add_column("Conclusion", justify="center")
    counts_table.add_column("Count", justify="center")
    counts_table.add_column("Means")

    present = [item.conclusion for item in report.findings]
    for conclusion in CONCLUSION_ORDER:
        count = present.count(conclusion)
        if not count:
            continue
        label = Text(conclusion.value, style=_conclusion_style(conclusion.value))
        counts_table.add_row(label, str(count), CONCLUSION_GLOSS[conclusion])
    console.print(counts_table)

    detail_table = Table(
        title="[bold]Detail[/bold]",
        show_header=True,
        header_style="bold cyan",
    )
    detail_table.add_column("Conclusion", justify="center")
    detail_table.add_column("Source", overflow="fold")
    detail_table.add_column("Type")
    detail_table.add_column("Target", overflow="fold")
    detail_table.add_column("Explanation", overflow="fold")
    detail_table.add_column("Evidence", overflow="fold")

    for item in report.findings:
        label = Text(item.conclusion.value, style=_conclusion_style(item.conclusion.value))
        detail_table.add_row(
            label,
            _short_id(item.source_canonical_id),
            item.relationship_type.value,
            _short_id(item.target_canonical_id),
            item.explanation,
            ", ".join(item.evidence_ids) or "-",
        )
    console.print(detail_table)


# --- YAML rendering ----------------------------------------------------------------


def _to_yaml(data: dict[str, Any], indent: int = 0) -> str:
    """Convert dict to YAML string."""
    lines = []
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_to_yaml(value, indent + 1))
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                lines.append(f"{prefix}{key}:")
                for item in value:
                    lines.append(f"{prefix}  - ")
                    lines.append(_to_yaml(item, indent + 2).lstrip())
            else:
                for item in value:
                    lines.append(f"{prefix}{key}: {item}")
        elif value is None:
            lines.append(f"{prefix}{key}: null")
        elif isinstance(value, bool):
            lines.append(f"{prefix}{key}: {str(value).lower()}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)


def render_why_yaml(report: WhyReport) -> str:
    resource = report.resource
    data = {
        "command": "why",
        "resource": {
            "canonical_id": resource.canonical_id,
            "type": resource.resource_type.value,
            "provider": resource.provider,
            "region": resource.region,
            "account": resource.account,
            "name": resource.name,
            "native_id": resource.native_id,
            "arn": resource.arn,
            "terraform_address": resource.terraform_address,
        },
        "relationships": {
            "outgoing": [
                {
                    "target": r.target_canonical_id,
                    "type": r.type.value,
                    "origin": r.origin.value,
                    "evidence": r.evidence_ids,
                }
                for r in report.outgoing
            ],
            "incoming": [
                {
                    "source": r.source_canonical_id,
                    "type": r.type.value,
                    "origin": r.origin.value,
                    "evidence": r.evidence_ids,
                }
                for r in report.incoming
            ],
        },
        "evidence": [
            {
                "id": e.evidence.id,
                "source": e.evidence.source.value,
                "type": e.evidence.type.value,
                "strength": e.evidence.strength.value,
                "explanation": e.evidence.explanation,
            }
            for e in report.evidence
        ],
        "findings": [
            {
                "id": f.id,
                "conclusion": f.conclusion.value,
                "explanation": f.explanation,
            }
            for f in report.findings
        ],
        "coverage_limitations": list(report.limitations),
    }
    return _to_yaml(data)


def _dependent_to_dict(dep: Dependent) -> dict[str, Any]:
    return {
        "canonical_id": dep.canonical_id,
        "depth": dep.depth,
        "kind": dep.kind.value,
        "path": dep.path,
        "provenance": dep.provenance,
        "evidence": dep.evidence_ids,
    }


def render_impact_yaml(report: ImpactReport) -> str:
    data = {
        "command": "impact",
        "subject": report.subject_canonical_id,
        "basis": report.basis.value,
        "depth": report.depth,
        "risk": report.risk.value,
        "dependents": [_dependent_to_dict(d) for d in report.dependents],
        "notes": list(report.notes),
    }
    return _to_yaml(data)


def render_simulate_yaml(report: SimulateReport) -> str:
    data = {
        "command": "simulate",
        "plan_path": report.plan_path,
        "overall_risk": report.risk.value,
        "targets": [
            {
                "address": t.address,
                "actions": [a.value for a in t.actions],
                "resolved": t.resolved,
                "canonical_id": t.canonical_id if t.resolved else None,
                "risk": t.risk.value if t.risk else None,
                "dependents": [_dependent_to_dict(d) for d in t.dependents],
                "notes": list(t.notes),
            }
            for t in report.targets
        ],
        "notes": list(report.notes),
    }
    return _to_yaml(data)


def render_reconcile_yaml(report: ReconcileReport) -> str:
    data = {
        "command": "reconcile",
        "scan_run_id": report.scan_run_id,
        "analysed_scan_run_id": report.analysed_scan_run_id,
        "counts": dict(sorted(report.counts.items())),
        "findings": [
            {
                "finding_id": f.finding_id,
                "conclusion": f.conclusion.value,
                "source": f.source_canonical_id,
                "target": f.target_canonical_id,
                "relationship_type": f.relationship_type.value,
                "explanation": f.explanation,
                "evidence": list(f.evidence_ids),
                "unavailable_sources": [source.value for source in f.unavailable_sources],
            }
            for f in report.findings
        ],
    }
    return _to_yaml(data)


# --- CSV rendering -----------------------------------------------------------------


def render_why_csv(report: WhyReport) -> str:
    resource = report.resource
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["command", "why"])
    writer.writerow(["canonical_id", resource.canonical_id])
    writer.writerow(["type", resource.resource_type.value])
    writer.writerow(["provider", resource.provider])
    writer.writerow(["region", resource.region or ""])
    writer.writerow(["account", resource.account or ""])
    writer.writerow(["name", resource.name or ""])
    writer.writerow(["native_id", resource.native_id or ""])
    writer.writerow(["arn", resource.arn or ""])
    writer.writerow(["terraform_address", resource.terraform_address or ""])
    writer.writerow([])
    writer.writerow(["relationships"])
    writer.writerow(["direction", "resource", "type", "origin", "evidence"])
    for r in report.outgoing:
        evidence = ";".join(r.evidence_ids)
        writer.writerow(["outgoing", r.target_canonical_id, r.type.value, r.origin.value, evidence])
    for r in report.incoming:
        evidence = ";".join(r.evidence_ids)
        writer.writerow(["incoming", r.source_canonical_id, r.type.value, r.origin.value, evidence])
    writer.writerow([])
    writer.writerow(["evidence"])
    writer.writerow(["id", "source", "type", "strength", "explanation"])
    for e in report.evidence:
        ev = e.evidence
        writer.writerow([ev.id, ev.source.value, ev.type.value, ev.strength.value, ev.explanation])
    writer.writerow([])
    writer.writerow(["findings"])
    writer.writerow(["id", "conclusion", "explanation"])
    for f in report.findings:
        writer.writerow([f.id, f.conclusion.value, f.explanation])
    writer.writerow([])
    writer.writerow(["coverage_limitations"])
    writer.writerow(["limitation"])
    for lim in report.limitations:
        writer.writerow([lim])

    return output.getvalue()


def render_impact_csv(report: ImpactReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["command", "impact"])
    writer.writerow(["subject", report.subject_canonical_id])
    writer.writerow(["basis", report.basis.value])
    writer.writerow(["depth", report.depth])
    writer.writerow(["risk", report.risk.value])
    writer.writerow([])
    writer.writerow(["dependents"])
    writer.writerow(["canonical_id", "depth", "kind", "path", "provenance", "evidence"])
    for d in report.dependents:
        prov_str = ";".join(d.provenance)
        ev_str = ";".join(d.evidence_ids)
        writer.writerow(
            [
                d.canonical_id,
                d.depth,
                d.kind.value,
                _path_display(d.path),
                prov_str,
                ev_str,
            ]
        )
    writer.writerow([])
    writer.writerow(["notes"])
    for note in report.notes:
        writer.writerow([note])

    return output.getvalue()


def render_simulate_csv(report: SimulateReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["command", "simulate"])
    writer.writerow(["plan_path", report.plan_path])
    writer.writerow(["overall_risk", report.risk.value])
    writer.writerow([])
    writer.writerow(["targets"])
    writer.writerow(
        [
            "address",
            "actions",
            "resolved",
            "canonical_id",
            "risk",
            "depth",
            "kind",
            "path",
            "provenance",
            "evidence",
        ]
    )
    for t in report.targets:
        for d in t.dependents:
            writer.writerow(
                [
                    t.address,
                    ";".join(a.value for a in t.actions),
                    "true" if t.resolved else "false",
                    t.canonical_id or "",
                    t.risk.value if t.risk else "",
                    d.depth,
                    d.kind.value,
                    _path_display(d.path),
                    ";".join(d.provenance),
                    ";".join(d.evidence_ids),
                ]
            )
        if not t.dependents:
            writer.writerow(
                [
                    t.address,
                    ";".join(a.value for a in t.actions),
                    "true" if t.resolved else "false",
                    t.canonical_id or "",
                    t.risk.value if t.risk else "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )
    writer.writerow([])
    writer.writerow(["notes"])
    for note in report.notes:
        writer.writerow([note])

    return output.getvalue()


def render_reconcile_csv(report: ReconcileReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["command", "reconcile"])
    writer.writerow(["scan_run_id", report.scan_run_id])
    writer.writerow(["analysed_scan_run_id", report.analysed_scan_run_id or ""])
    writer.writerow([])
    writer.writerow(["counts"])
    writer.writerow(["conclusion", "count"])
    for conclusion in CONCLUSION_ORDER:
        count = report.counts.get(conclusion.value, 0)
        if count:
            writer.writerow([conclusion.value, count])
    writer.writerow([])
    writer.writerow(["findings"])
    writer.writerow(
        [
            "finding_id",
            "conclusion",
            "source",
            "relationship_type",
            "target",
            "unavailable_sources",
            "evidence",
            "explanation",
        ]
    )
    for f in report.findings:
        writer.writerow(
            [
                f.finding_id,
                f.conclusion.value,
                f.source_canonical_id,
                f.relationship_type.value,
                f.target_canonical_id,
                ";".join(source.value for source in f.unavailable_sources),
                ";".join(f.evidence_ids),
                f.explanation,
            ]
        )

    return output.getvalue()


def stable_json(model: BaseModel) -> str:
    """Byte-stable JSON for any report: sorted keys, no timestamps, no scores.

    Reports rendered this way are comparable across runs — the same database
    and inputs always produce the same bytes.
    """
    return json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True)


# --- Legacy text rendering (for backward compatibility) ----------------------------


def _render_dependents(dependents: Sequence[Dependent], indent: str) -> list[str]:
    if not dependents:
        return [f"{indent}dependents: none"]
    lines = [f"{indent}dependents ({len(dependents)}):"]
    for dependent in dependents:
        lines.append(
            f"{indent}  - {dependent.canonical_id} "
            f"(depth {dependent.depth}, {dependent.kind.value})"
        )
        lines.append(f"{indent}      path: {_path_display(dependent.path)}")
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
