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
from reality.domain.ids import IdParseError, parse_canonical
from reality.domain.models import Coverage, Finding, Relationship, Resource
from reality.services.graph import IdentityResolver
from reality.services.hidden_dependencies import ConfidenceBand, HiddenDependency
from reality.services.impact import (
    VERDICT_GLOSS,
    Dependent,
    DependentCounts,
    DependentKind,
    ImpactReport,
    SimulateReport,
    Verdict,
)
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
    "install it with: pip install 'reality[table]' "
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
        self._resolver = IdentityResolver(store.resources.all(), store.relationships.all())

    def explain(self, canonical_id: str) -> WhyReport | None:
        """The resource's evidence trail, or ``None`` if it was never stored."""
        context = self._store.get_resource_context(canonical_id, resolver=self._resolver)
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


def _missing_coverage(report: ReconcileReport) -> list[str]:
    """One ``source (n)`` entry per source that blocked a conclusion.

    Sorted by how many conclusions it blocked, then by name so the summary is
    byte-stable. This is the actionable part of a summary: it names the inputs
    the operator did not supply, which is what turns UNKNOWN into a fixable
    next step rather than a shrug.
    """
    counts: dict[EvidenceSource, int] = {}
    for item in report.findings:
        for source in item.unavailable_sources:
            counts[source] = counts.get(source, 0) + 1
    ordered = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0].value))
    return [f"{source.value} ({count})" for source, count in ordered]


# --- the declared-vs-observed comparison ------------------------------------------

#: Column width cap for the comparison view: wide enough for a Terraform
#: address or an AWS native ID, narrow enough that three columns still fit an
#: 80-column terminal.
_COMPARE_WIDTH = 28


def _truncate(text: str, width: int) -> str:
    """Shorten to ``width``, keeping the tail.

    The tail is the informative end of both forms this column holds: the name
    in a Terraform address (``…security_group.web_sg``) and the resource in an
    ARN. Cutting from the front leaves ``aws_security_gro...``, which is the
    half every row has in common.
    """
    return text if len(text) <= width else "..." + text[-(width - 3) :]


def _compare_label(canonical_id: str) -> str:
    """The shortest identifier a human recognizes a resource by.

    The Terraform address for the declared world, the native ID or name for
    the observed one. Deliberately lossy — two resources of different types can
    share a name — so this form is only ever used for display and the full
    canonical IDs stay available under ``--verbose``.
    """
    try:
        return parse_canonical(canonical_id).resource_id
    except IdParseError:
        return canonical_id


#: What an empty DECLARED column means, per conclusion. Only for UNDOCUMENTED
#: is the absence itself the finding; a permission grant has no Terraform
#: counterpart to be missing, so saying "nothing declares it" there would read
#: as drift that was never claimed.
_NO_DECLARATION: dict[Conclusion, str] = {
    Conclusion.UNDOCUMENTED: "nothing declares it",
    Conclusion.POSSIBLE: "n/a - iam grant",
}


def _comparison_rows(report: ReconcileReport) -> list[ReconciledRelationship]:
    """One row per real dependency, drift first.

    A joined group emits a finding per namespace, so findings are collapsed on
    :attr:`ReconciledRelationship.comparison_key` — otherwise a confirmed
    dependency would appear twice, once from each world's point of view.
    """
    by_key: dict[tuple[str, str, str], ReconciledRelationship] = {}
    for item in report.findings:
        by_key.setdefault(item.comparison_key, item)
    ordered: list[ReconciledRelationship] = []
    for conclusion in CONCLUSION_ORDER:
        rows = [item for item in by_key.values() if item.conclusion is conclusion]
        rows.sort(key=lambda item: (item.source_canonical_id, item.target_canonical_id))
        ordered.extend(rows)
    return ordered


#: Shown wherever finding counts sit next to the collapsed comparison rows, so
#: "confirmed 6" beside three confirmed rows reads as bookkeeping, not a bug.
_PER_SIDE_NOTE = "a dependency both worlds agree on is one row but one finding per side"


def _row_counts(report: ReconcileReport) -> dict[Conclusion, int]:
    """Per-conclusion counts of the comparison rows, not the stored findings."""
    counts: dict[Conclusion, int] = {}
    for item in _comparison_rows(report):
        counts[item.conclusion] = counts.get(item.conclusion, 0) + 1
    return counts


def _compare_cells(item: ReconciledRelationship, width: int) -> tuple[str, str, str, str, str, str]:
    """The six cells of one comparison row: declared, observed and verdict, x2 lines.

    Truncation happens here rather than in the caller so the ``-> `` marker on
    a target line survives it: eliding the whole cell would drop the arrow and
    leave the second line looking like a wrapped continuation.
    """

    def target(canonical_id: str, room: int) -> str:
        return f"-> {_truncate(_compare_label(canonical_id), room - 3)}"

    if item.declared_edge is not None:
        declared_head = _truncate(_compare_label(item.declared_edge[0]), width - 2)
        declared_tail = target(item.declared_edge[1], width - 4)
    else:
        declared_head = "-"
        declared_tail = _NO_DECLARATION.get(item.conclusion, "not declared")

    if item.observed_edge is not None:
        observed_head = _truncate(_compare_label(item.observed_edge[0]), width - 2)
        observed_tail = target(item.observed_edge[1], width - 2)
    else:
        observed_head = "-"
        observed_tail = "not observed"

    verdict_head = (
        item.conclusion.value.upper()
        if item.conclusion is Conclusion.UNDOCUMENTED
        else item.conclusion.value
    )
    verdict_tail = f"[{item.relationship_type.value}]"
    if item.joined_by is not None:
        verdict_tail += f" joined by {item.joined_by.value}"
    return declared_head, declared_tail, observed_head, observed_tail, verdict_head, verdict_tail


def render_comparison(report: ReconcileReport) -> list[str]:
    """The declared-vs-observed comparison, as aligned plain-text lines.

    This is the view the tool exists for: what Terraform declared, what AWS
    reported, and the conclusion drawn from having both side by side. Drift
    sorts to the top, because that is the row that changes what someone does
    next.
    """
    rows = _comparison_rows(report)
    if not rows:
        return []
    width = _COMPARE_WIDTH
    lines = [
        f"  {'DECLARED (terraform)':<{width}}{'OBSERVED (aws)':<{width}}VERDICT",
        "  " + "-" * (width * 2 + 24),
    ]
    for item in rows:
        d_head, d_tail, o_head, o_tail, v_head, v_tail = _compare_cells(item, width)
        lines.append(f"  {d_head:<{width}}{o_head:<{width}}{v_head}")
        lines.append(f"    {d_tail:<{width - 2}}{o_tail:<{width}}{v_tail}")
        lines.append("")
    return lines


def _legend(report: ReconcileReport) -> list[str]:
    """One line per conclusion actually present, so the table explains itself."""
    present = [
        conclusion
        for conclusion in CONCLUSION_ORDER
        if any(item.conclusion is conclusion for item in report.findings)
    ]
    if not present:
        return []
    width = max(len(conclusion.value) for conclusion in present)
    return [
        "  legend:",
        *(
            f"    {conclusion.value:<{width}}  {CONCLUSION_GLOSS[conclusion]}"
            for conclusion in present
        ),
    ]


def render_reconcile(report: ReconcileReport, *, verbose: bool = False) -> str:
    analysed = (
        f"comparing scan run {report.analysed_scan_run_id}"
        if report.analysed_scan_run_id is not None
        else "no snapshot analysed"
    )
    lines = [
        f"reality: reconcile pass {report.scan_run_id} ({analysed})",
        f"  findings ({len(report.findings)}): {_conclusion_counts(report) or 'none'}",
    ]
    if not report.findings:
        lines.append("  none; the snapshot held no relationship candidates to compare")
        return "\n".join(lines) + "\n"

    rows = len(_comparison_rows(report))
    if not verbose and rows != len(report.findings):
        lines.append(f"  shown below as {rows} dependencies; {_PER_SIDE_NOTE}")

    drift = sum(1 for item in report.findings if item.conclusion is Conclusion.UNDOCUMENTED)
    if drift:
        lines.append(
            f"  {drift} observed dependenc{'y' if drift == 1 else 'ies'} "
            "no declaration accounts for"
        )
    lines.append("")

    if verbose:
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
    else:
        lines.extend(render_comparison(report))
        lines.extend(_legend(report))
        lines.append("  full canonical IDs and per-finding reasoning: --verbose")

    missing_summary = _missing_coverage(report)
    if missing_summary:
        lines.append(f"  missing coverage: {', '.join(missing_summary)}")

    return "\n".join(lines) + "\n"


# --- rich table rendering ---------------------------------------------------------


def _verdict_style(verdict: str) -> str:
    """Rich style for a blast-radius verdict."""
    styles = {
        Verdict.UNDOCUMENTED_DEPENDENTS.value: "bold red",
        Verdict.INCONCLUSIVE.value: "bold yellow",
        Verdict.DEPENDENTS_DOCUMENTED.value: "cyan",
        Verdict.NO_DEPENDENTS_FOUND.value: "bold green",
    }
    return styles.get(verdict.lower(), "dim")


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
    """Rich style for a dependent kind.

    Keyed on the :class:`~reality.services.impact.DependentKind` values, which
    say how well documented a dependency is — not on graph-distance words,
    which is what this table used to colour by and never matched.
    """
    styles = {
        DependentKind.UNDOCUMENTED.value: "bold red",
        DependentKind.UNKNOWN.value: "yellow",
        DependentKind.POSSIBLE.value: "yellow",
        DependentKind.DOCUMENTED.value: "green",
    }
    return styles.get(kind.lower(), "dim")


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
    console = Console()

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
                finding.conclusion.value, style=_conclusion_style(finding.conclusion.value)
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
    console = Console()

    verdict_text = Text(report.verdict.value, style=_verdict_style(report.verdict.value))
    subject_short = _short_id(report.subject_canonical_id)
    console.print(f"[bold cyan]reality: impact of {subject_short}[/bold cyan]")
    console.print(f"  Verdict:    {verdict_text}  [dim]{VERDICT_GLOSS[report.verdict]}[/dim]")
    console.print(f"  Dependents: [bold]{report.counts.summary()}[/bold]")
    console.print(f"  [dim]Basis: {report.basis.value} | Depth: {report.depth}[/dim]")

    _render_dependents_table(report.dependents, console, "  ")

    if report.notes:
        console.print("\n[bold]Notes:[/bold]")
        for note in report.notes:
            console.print(f"  - {_short_ids_in_text(note)}")


def render_simulate_table(report: SimulateReport) -> None:
    Console, _, Text = _rich()
    console = Console()

    overall = report.verdict.value if report.verdict is not None else "not_assessed"
    overall_text = Text(overall, style=_verdict_style(overall))
    gloss = (
        VERDICT_GLOSS[report.verdict]
        if report.verdict is not None
        else "no target could be assessed"
    )
    console.print(f"[bold cyan]reality: simulate {report.plan_path}[/bold cyan]")
    console.print("  [dim]read-only; the plan is never applied[/dim]")
    console.print(f"  Verdict:    {overall_text}  [dim]{gloss}[/dim]")
    console.print(f"  Assessment: {report.assessment.value}")
    console.print(f"  Dependents: {report.counts.summary()}")
    console.print(f"  Targets:    {len(report.targets)}")

    if not report.targets:
        console.print("[dim]  No delete or replace targets in plan[/dim]")
    else:
        for i, target in enumerate(report.targets):
            actions = ", ".join(action.value for action in target.actions)
            canonical = target.canonical_id if target.resolved and target.canonical_id else None
            dest = _short_id(canonical) if canonical else "[red]unresolved[/red]"
            value = target.verdict.value if target.verdict is not None else "not_assessed"
            verdict_text = Text(value, style=_verdict_style(value))
            target_gloss = (
                VERDICT_GLOSS[target.verdict]
                if target.verdict is not None
                else "target could not be assessed"
            )

            console.print(
                f"\n  [bold]Target {i + 1}:[/bold] {target.address} [{actions}] -> {dest}"
            )
            console.print(f"    Verdict: {verdict_text}  [dim]{target_gloss}[/dim]")

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
    console = Console()

    analysed = (
        f"comparing scan run {report.analysed_scan_run_id}"
        if report.analysed_scan_run_id is not None
        else "no snapshot analysed"
    )
    console.print(f"[bold cyan]reality: reconcile pass {report.scan_run_id}[/bold cyan]")
    console.print(f"  [dim]{analysed}[/dim]")
    console.print(f"  Findings: [bold]{len(report.findings)}[/bold]")

    if not report.findings:
        console.print("[dim]  No relationship candidates to compare in this snapshot[/dim]")
        return

    rows = _comparison_rows(report)
    if len(rows) != len(report.findings):
        console.print(f"  Dependencies: [bold]{len(rows)}[/bold]  [dim]({_PER_SIDE_NOTE})[/dim]")

    drift = sum(1 for item in report.findings if item.conclusion is Conclusion.UNDOCUMENTED)
    if drift:
        console.print(
            f"  [bold red]{drift} observed dependenc{'y' if drift == 1 else 'ies'} "
            "no declaration accounts for[/bold red]"
        )

    compare_table = Table(
        title="[bold]Declared vs observed[/bold]",
        show_header=True,
        header_style="bold cyan",
    )
    compare_table.add_column("DECLARED (terraform)", overflow="fold")
    compare_table.add_column("OBSERVED (aws)", overflow="fold")
    compare_table.add_column("Type")
    compare_table.add_column("Verdict", justify="center")
    compare_table.add_column("Joined by", justify="center")

    for item in rows:
        declared = (
            f"{_compare_label(item.declared_edge[0])}\n  -> {_compare_label(item.declared_edge[1])}"
            if item.declared_edge is not None
            else f"[dim]{_NO_DECLARATION.get(item.conclusion, 'not declared')}[/dim]"
        )
        observed = (
            f"{_compare_label(item.observed_edge[0])}\n  -> {_compare_label(item.observed_edge[1])}"
            if item.observed_edge is not None
            else "[dim]not observed[/dim]"
        )
        compare_table.add_row(
            declared,
            observed,
            item.relationship_type.value,
            Text(item.conclusion.value, style=_conclusion_style(item.conclusion.value)),
            item.joined_by.value if item.joined_by is not None else "-",
        )
    console.print(compare_table)

    counts_table = Table(
        title="[bold]Findings by conclusion[/bold]",
        caption=f"[dim]{_PER_SIDE_NOTE}[/dim]" if len(rows) != len(report.findings) else None,
        show_header=True,
        header_style="bold cyan",
    )
    counts_table.add_column("Conclusion", justify="center")
    counts_table.add_column("Rows", justify="center")
    counts_table.add_column("Findings", justify="center")
    counts_table.add_column("Means")

    present = [item.conclusion for item in report.findings]
    row_counts = _row_counts(report)
    for conclusion in CONCLUSION_ORDER:
        count = present.count(conclusion)
        if not count:
            continue
        label = Text(conclusion.value, style=_conclusion_style(conclusion.value))
        counts_table.add_row(
            label, str(row_counts.get(conclusion, 0)), str(count), CONCLUSION_GLOSS[conclusion]
        )
    console.print(counts_table)

    missing_summary = _missing_coverage(report)
    if missing_summary:
        console.print(f"  [yellow]missing coverage:[/yellow] {', '.join(missing_summary)}")


# --- YAML rendering ----------------------------------------------------------------


def _yaml_scalar(value: Any) -> str:
    """One YAML scalar.

    Strings are emitted as JSON double-quoted strings, which are also valid
    YAML double-quoted scalars. Quoting unconditionally is what keeps the
    output parseable at all: nearly every explanation in a report contains
    ``: `` or ``#``, and a plain scalar containing ``: `` parses as a nested
    mapping rather than as text.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    return json.dumps(str(value))


def _yaml_lines(data: Any, indent: int = 0) -> list[str]:
    """Render a JSON-shaped value as YAML lines at the given indent level."""
    pad = "  " * indent
    if isinstance(data, dict):
        if not data:
            return [f"{pad}{{}}"]
        lines: list[str] = []
        for key, value in data.items():
            if isinstance(value, dict | list | tuple):
                if not value:
                    lines.append(f"{pad}{key}: " + ("{}" if isinstance(value, dict) else "[]"))
                else:
                    lines.append(f"{pad}{key}:")
                    lines.extend(_yaml_lines(value, indent + 1))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(value)}")
        return lines
    if isinstance(data, list | tuple):
        if not data:
            return [f"{pad}[]"]
        lines = []
        for item in data:
            if isinstance(item, dict) and item:
                # The first key sits on the dash line; `indent + 1` puts the
                # remaining keys in the same column, which is what makes them
                # siblings rather than a new nesting level.
                nested = _yaml_lines(item, indent + 1)
                lines.append(f"{pad}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
        return lines
    return [f"{pad}{_yaml_scalar(data)}"]


def _to_yaml(data: dict[str, Any]) -> str:
    """A report as YAML. Hand-rolled so no output format needs a dependency."""
    return "\n".join(_yaml_lines(data))


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


def _counts_to_dict(counts: DependentCounts) -> dict[str, Any]:
    return {
        "total": counts.total,
        "documented": counts.documented,
        "undocumented": counts.undocumented,
        "possible": counts.possible,
        "unknown": counts.unknown,
    }


def render_impact_yaml(report: ImpactReport) -> str:
    data = {
        "command": "impact",
        "subject": report.subject_canonical_id,
        "basis": report.basis.value,
        "depth": report.depth,
        "verdict": report.verdict.value,
        "verdict_means": VERDICT_GLOSS[report.verdict],
        "counts": _counts_to_dict(report.counts),
        "dependents": [_dependent_to_dict(d) for d in report.dependents],
        "notes": list(report.notes),
    }
    return _to_yaml(data)


def render_simulate_yaml(report: SimulateReport) -> str:
    data = {
        "command": "simulate",
        "plan_path": report.plan_path,
        "assessment": report.assessment.value,
        "verdict": report.verdict.value if report.verdict is not None else None,
        "verdict_means": (VERDICT_GLOSS[report.verdict] if report.verdict is not None else None),
        "counts": _counts_to_dict(report.counts),
        "targets": [
            {
                "address": t.address,
                "actions": [a.value for a in t.actions],
                "resolved": t.resolved,
                "canonical_id": t.canonical_id if t.resolved else None,
                "verdict": t.verdict.value if t.verdict else None,
                "counts": _counts_to_dict(t.counts),
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
                "declared_edge": list(f.declared_edge) if f.declared_edge else None,
                "observed_edge": list(f.observed_edge) if f.observed_edge else None,
                "joined_by": f.joined_by.value if f.joined_by else None,
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
    writer.writerow(["verdict", report.verdict.value])
    writer.writerow(["verdict_means", VERDICT_GLOSS[report.verdict]])
    writer.writerow([])
    writer.writerow(["counts"])
    writer.writerow(["total", "documented", "undocumented", "possible", "unknown"])
    writer.writerow(
        [
            report.counts.total,
            report.counts.documented,
            report.counts.undocumented,
            report.counts.possible,
            report.counts.unknown,
        ]
    )
    writer.writerow([])
    writer.writerow(["dependents"])
    writer.writerow(["canonical_id", "depth", "kind", "path", "provenance", "evidence"])
    for d in report.dependents:
        writer.writerow(
            [
                d.canonical_id,
                d.depth,
                d.kind.value,
                _path_display(d.path),
                ";".join(d.provenance),
                ";".join(d.evidence_ids),
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
    writer.writerow(["assessment", report.assessment.value])
    writer.writerow(["verdict", report.verdict.value if report.verdict is not None else ""])
    writer.writerow([])
    writer.writerow(["targets"])
    writer.writerow(
        [
            "address",
            "actions",
            "resolved",
            "canonical_id",
            "verdict",
            "depth",
            "kind",
            "path",
            "provenance",
            "evidence",
        ]
    )
    for t in report.targets:
        head = [
            t.address,
            ";".join(a.value for a in t.actions),
            "true" if t.resolved else "false",
            t.canonical_id or "",
            t.verdict.value if t.verdict else "",
        ]
        if not t.dependents:
            writer.writerow([*head, "", "", "", "", ""])
            continue
        for d in t.dependents:
            writer.writerow(
                [
                    *head,
                    d.depth,
                    d.kind.value,
                    _path_display(d.path),
                    ";".join(d.provenance),
                    ";".join(d.evidence_ids),
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
            "declared_source",
            "declared_target",
            "observed_source",
            "observed_target",
            "joined_by",
            "unavailable_sources",
            "evidence",
            "explanation",
        ]
    )
    for f in report.findings:
        declared = f.declared_edge or ("", "")
        observed = f.observed_edge or ("", "")
        writer.writerow(
            [
                f.finding_id,
                f.conclusion.value,
                f.source_canonical_id,
                f.relationship_type.value,
                f.target_canonical_id,
                declared[0],
                declared[1],
                observed[0],
                observed[1],
                f.joined_by.value if f.joined_by else "",
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


# --- hidden dependencies ------------------------------------------------------------


class DriftReport(BaseModel):
    """The hidden dependencies one reconciliation pass turned up.

    A thin wrapper so ``reality drift`` has a report object like every other
    command — same ``--output`` paths, same byte-stable JSON.
    """

    model_config = ConfigDict(frozen=True)

    scan_run_id: int
    analysed_scan_run_id: int | None = None
    hidden: tuple[HiddenDependency, ...] = ()


def _band_style(band: str) -> str:
    """Rich style for a confidence band.

    Unlike the retired risk bands, this one is defensible: it is derived
    directly from the strength of the evidence behind the finding, which is a
    property of the evidence rather than a guess about business impact.
    """
    styles = {
        ConfidenceBand.STRONG.value: "bold red",
        ConfidenceBand.MODERATE.value: "yellow",
        ConfidenceBand.WEAK.value: "dim",
    }
    return styles.get(band.lower(), "")


def render_drift(report: DriftReport) -> str:
    analysed = (
        f"from scan run {report.analysed_scan_run_id}"
        if report.analysed_scan_run_id is not None
        else "no snapshot analysed"
    )
    lines = [
        f"reality: drift ({analysed})",
        f"  hidden dependencies ({len(report.hidden)}):",
    ]
    if not report.hidden:
        lines.append(
            "    none; no observed dependency lacks a declaration, or none is backed "
            "by observed evidence"
        )
        return "\n".join(lines) + "\n"
    for item in report.hidden:
        lines.append(
            f"    - {item.source_canonical_id} -> {item.target_canonical_id} "
            f"[{item.relationship_type.value}]"
        )
        lines.append(f"        confidence: {item.band.value}")
        lines.append(f"        {item.rationale}")
        if item.evidence_ids:
            lines.append(f"        evidence: {', '.join(item.evidence_ids)}")
    return "\n".join(lines) + "\n"


def render_drift_table(report: DriftReport) -> None:
    Console, Table, Text = _rich()
    console = Console()

    analysed = (
        f"from scan run {report.analysed_scan_run_id}"
        if report.analysed_scan_run_id is not None
        else "no snapshot analysed"
    )
    console.print("[bold cyan]reality: drift[/bold cyan]")
    console.print(f"  [dim]{analysed}[/dim]")
    console.print(f"  Hidden dependencies: [bold]{len(report.hidden)}[/bold]")
    if not report.hidden:
        console.print(
            "[dim]  None: no observed dependency lacks a declaration, or none is "
            "backed by observed evidence[/dim]"
        )
        return

    table = Table(
        title="[bold]Observed, but undeclared[/bold]",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Source", overflow="fold")
    table.add_column("Target", overflow="fold")
    table.add_column("Type")
    table.add_column("Confidence", justify="center")
    table.add_column("Why", overflow="fold")

    for item in report.hidden:
        table.add_row(
            _short_id(item.source_canonical_id),
            _short_id(item.target_canonical_id),
            item.relationship_type.value,
            Text(item.band.value, style=_band_style(item.band.value)),
            item.rationale,
        )
    console.print(table)


def _hidden_to_dict(item: HiddenDependency) -> dict[str, Any]:
    return {
        "finding_id": item.finding_id,
        "source": item.source_canonical_id,
        "target": item.target_canonical_id,
        "relationship_type": item.relationship_type.value,
        "confidence": item.band.value,
        "rationale": item.rationale,
        "evidence": list(item.evidence_ids),
    }


def render_drift_yaml(report: DriftReport) -> str:
    return _to_yaml(
        {
            "command": "drift",
            "scan_run_id": report.scan_run_id,
            "analysed_scan_run_id": report.analysed_scan_run_id,
            "hidden": [_hidden_to_dict(item) for item in report.hidden],
        }
    )


def render_drift_csv(report: DriftReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["command", "drift"])
    writer.writerow(["scan_run_id", report.scan_run_id])
    writer.writerow(["analysed_scan_run_id", report.analysed_scan_run_id or ""])
    writer.writerow([])
    writer.writerow(
        ["finding_id", "source", "target", "relationship_type", "confidence", "evidence", "why"]
    )
    for item in report.hidden:
        writer.writerow(
            [
                item.finding_id,
                item.source_canonical_id,
                item.target_canonical_id,
                item.relationship_type.value,
                item.band.value,
                ";".join(item.evidence_ids),
                item.rationale,
            ]
        )
    return output.getvalue()


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
        f"reality: impact of {report.subject_canonical_id}",
        f"  verdict:    {report.verdict.value} - {VERDICT_GLOSS[report.verdict]}",
        f"  dependents: {report.counts.summary()}",
        f"  basis:      {report.basis.value}, depth {report.depth}",
    ]
    lines.extend(_render_dependents(report.dependents, "  "))
    if report.notes:
        lines.append("  notes:")
        lines.extend(f"    - {note}" for note in report.notes)
    return "\n".join(lines) + "\n"


def render_simulate(report: SimulateReport) -> str:
    overall = (
        f"{report.verdict.value} - {VERDICT_GLOSS[report.verdict]}"
        if report.verdict is not None
        else "not_assessed - no target could be assessed"
    )
    lines = [
        f"reality: simulate {report.plan_path} (read-only; the plan is never applied)",
        f"  verdict:    {overall}",
        f"  assessment: {report.assessment.value}",
        f"  dependents: {report.counts.summary()}",
        f"  targets ({len(report.targets)}):",
    ]
    if not report.targets:
        lines.append("    none")
    for target in report.targets:
        actions = ", ".join(action.value for action in target.actions)
        destination = target.canonical_id if target.resolved else "unresolved"
        lines.append(f"    - {target.address} [{actions}] -> {destination}")
        if target.verdict is None:
            lines.append("        verdict: not_assessed - target could not be assessed")
        else:
            lines.append(
                f"        verdict: {target.verdict.value} - {VERDICT_GLOSS[target.verdict]}"
            )
        lines.extend(_render_dependents(target.dependents, "        "))
        lines.extend(f"        note: {note}" for note in target.notes)
    if report.notes:
        lines.append("  notes:")
        lines.extend(f"    - {note}" for note in report.notes)
    return "\n".join(lines) + "\n"
