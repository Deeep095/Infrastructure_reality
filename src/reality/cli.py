"""Command-line interface for reality.

``scan`` runs the orchestrator from :mod:`reality.services.scan` (local
Terraform JSON paths, plus the opted-in AWS/IAM/CloudTrail sources).
``reconcile`` compares one scan run's declared and observed candidates and
writes the conclusions as separate finding rows. ``why``/``impact``/``simulate``
are read-only reports from the stored database: they open it without migrating
or writing, and ``simulate`` parses a local plan JSON without ever running
Terraform or contacting AWS.

Exit codes:
    0  success
    2  usage error (argparse)
    3  command registered but not implemented yet
    4  configuration rejected by the safety contract
    5  invalid local input (a scan or simulation refused before writing
       anything, or a resource the database has never seen)
    6  a ``--fail-on`` threshold was met; the report was still printed
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import cast

from reality.config import ConfigError, RealityConfig
from reality.domain.ids import parse_canonical
from reality.domain.models import Resource
from reality.services.impact import (
    DEFAULT_DEPTH,
    ImpactReport,
    ImpactService,
    RiskLevel,
    SimulateReport,
    SimulateService,
)
from reality.services.reconcile import ReconcileReport, ReconcileService
from reality.services.reports import (
    MissingTableExtra,
    WhyReport,
    WhyService,
    render_impact,
    render_impact_csv,
    render_impact_table,
    render_impact_yaml,
    render_reconcile,
    render_reconcile_csv,
    render_reconcile_table,
    render_reconcile_yaml,
    render_simulate,
    render_simulate_csv,
    render_simulate_table,
    render_simulate_yaml,
    render_why,
    render_why_csv,
    render_why_table,
    render_why_yaml,
    stable_json,
)
from reality.services.scan import ScanInputError, ScanReport, ScanService
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3
EXIT_CONFIG = 4
EXIT_INPUT = 5
EXIT_POLICY = 6


class OutputFormat:
    """Supported output formats for read-only commands."""

    TEXT = "text"
    TABLE = "table"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"
    ALL = (TEXT, TABLE, JSON, YAML, CSV)


class FailOn:
    """``--fail-on`` thresholds, from permissive to strictest.

    ``NEVER`` is the default because deciding what to do about a risky report
    is a policy question that belongs to the caller, not to this tool: the
    report is always printed, and the exit code only reports whether the
    caller's own threshold was met.
    """

    NEVER = "never"
    MEDIUM = "medium"
    HIGH = "high"
    ALL = (NEVER, MEDIUM, HIGH)


#: The lowest band that satisfies each threshold.
_FAIL_ON_BAND: dict[str, RiskLevel] = {
    FailOn.MEDIUM: RiskLevel.MEDIUM,
    FailOn.HIGH: RiskLevel.HIGH,
}

#: Bands ordered most to least severe, for the threshold comparison.
_SEVERITY: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
}


class CommandNotImplemented(Exception):
    """A registered command whose behaviour arrives in a later phase."""


def _positive_int(value: str) -> int:
    """argparse type for --depth: an integer of at least 1."""
    try:
        depth = int(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from err
    if depth < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return depth


def _add_common_flags(parser: argparse.ArgumentParser, *, global_defaults: bool) -> None:
    """Add the flags that work both before and after the subcommand.

    ``--database``, ``--aws``, ``--profile`` and ``--region`` are global, but
    users routinely type them after the subcommand and get an unexplained
    "unrecognized arguments". Accepting them in both positions removes that
    trap. On the subparsers every default is ``argparse.SUPPRESS`` so a flag
    given only to the global parser is never overwritten by a default.
    """
    parser.add_argument(
        "--database",
        type=Path,
        default=RealityConfig().database_path if global_defaults else argparse.SUPPRESS,
        help="local SQLite database file (default: %(default)s)",
    )
    parser.add_argument(
        "--aws",
        action="store_true",
        default=False if global_defaults else argparse.SUPPRESS,
        help="explicitly allow read-only AWS calls",
    )
    parser.add_argument(
        "--profile",
        default=None if global_defaults else argparse.SUPPRESS,
        help="named AWS profile; required with --aws",
    )
    parser.add_argument(
        "--region",
        default=None if global_defaults else argparse.SUPPRESS,
        help="AWS region; required with --aws",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser. Global flags work before or after the subcommand."""
    parser = argparse.ArgumentParser(
        prog="reality",
        description=(
            "Read-only cloud infrastructure discovery and local blast-radius "
            "simulation. Never applies, destroys, or refreshes infrastructure."
        ),
    )
    _add_common_flags(parser, global_defaults=True)

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser(
        "scan",
        help="discover resources from selected sources into the local database",
    )
    _add_common_flags(scan, global_defaults=False)
    scan.add_argument(
        "paths",
        nargs="*",
        type=Path,
        metavar="TFJSON",
        help="`terraform show -json` file(s) the user exported: state or plan documents",
    )
    scan.add_argument(
        "--cloudtrail-start",
        help="start of the CloudTrail lookup window, ISO-8601 with UTC offset (requires --aws)",
    )
    scan.add_argument(
        "--cloudtrail-end",
        help="end of the CloudTrail lookup window, ISO-8601 with UTC offset (requires --aws)",
    )
    rec = sub.add_parser(
        "reconcile",
        help="compare declared (Terraform) and observed (AWS) candidates for one scan run",
    )
    _add_common_flags(rec, global_defaults=False)
    rec.add_argument(
        "--scan-run",
        type=int,
        help="analyse this discovery scan run instead of the latest one",
    )
    rec.add_argument(
        "--output",
        choices=OutputFormat.ALL,
        default=OutputFormat.TEXT,
        help="output format (default: %(default)s)",
    )
    rec.add_argument(
        "--json",
        action="store_true",
        help="alias for --output json",
    )
    why = sub.add_parser("why", help="explain why a resource exists (evidence and conclusions)")
    _add_common_flags(why, global_defaults=False)
    why.add_argument("resource", help="canonical ID, Terraform address, ARN, or native ID")
    why.add_argument(
        "--output",
        choices=OutputFormat.ALL,
        default=OutputFormat.TEXT,
        help="output format (default: %(default)s)",
    )
    why.add_argument(
        "--json",
        action="store_true",
        help="alias for --output json",
    )
    impact = sub.add_parser("impact", help="report the blast radius of a resource")
    _add_common_flags(impact, global_defaults=False)
    impact.add_argument("resource", help="canonical ID, Terraform address, ARN, or native ID")
    impact.add_argument(
        "--depth",
        type=_positive_int,
        default=DEFAULT_DEPTH,
        help="maximum traversal depth for dependents (default: %(default)s)",
    )
    impact.add_argument(
        "--output",
        choices=OutputFormat.ALL,
        default=OutputFormat.TEXT,
        help="output format (default: %(default)s)",
    )
    impact.add_argument(
        "--json",
        action="store_true",
        help="alias for --output json",
    )
    impact.add_argument(
        "--fail-on",
        choices=FailOn.ALL,
        default=FailOn.NEVER,
        help=(
            f"exit {EXIT_POLICY} when the blast radius reaches this band; "
            "the report is printed either way (default: %%(default)s)"
        ),
    )

    simulate = sub.add_parser(
        "simulate",
        help="compute blast radius from an exported Terraform plan JSON (never applies it)",
    )
    _add_common_flags(simulate, global_defaults=False)
    simulate.add_argument("plan_json", help="path to a `terraform show -json` plan file")
    simulate.add_argument(
        "--depth",
        type=_positive_int,
        default=DEFAULT_DEPTH,
        help="maximum traversal depth per target (default: %(default)s)",
    )
    simulate.add_argument(
        "--output",
        choices=OutputFormat.ALL,
        default=OutputFormat.TEXT,
        help="output format (default: %(default)s)",
    )
    simulate.add_argument(
        "--json",
        action="store_true",
        help="alias for --output json",
    )
    simulate.add_argument(
        "--fail-on",
        choices=FailOn.ALL,
        default=FailOn.NEVER,
        help=(
            f"exit {EXIT_POLICY} when the overall risk reaches this band; "
            "the report is printed either way (default: %%(default)s)"
        ),
    )

    return parser


def _dispatch(command: str, config: RealityConfig, args: argparse.Namespace) -> int:
    """Run a command and return its exit code."""
    if command == "scan":
        _run_scan(config, args)
    elif command == "reconcile":
        return _run_reconcile(config, args)
    elif command == "why":
        _run_why(config, args)
    elif command == "impact":
        return _run_impact(config, args)
    elif command == "simulate":
        return _run_simulate(config, args)
    return EXIT_OK


def _cloudtrail_window(
    config: RealityConfig, args: argparse.Namespace
) -> tuple[datetime, datetime] | None:
    """Parse the optional CloudTrail window; ``None`` leaves the source unrequested."""
    start_raw, end_raw = args.cloudtrail_start, args.cloudtrail_end
    if start_raw is None and end_raw is None:
        return None
    if not config.aws_ready:
        raise ConfigError(
            "--cloudtrail-start/--cloudtrail-end select AWS usage; rerun with "
            "--aws --profile PROFILE --region REGION"
        )
    if start_raw is None or end_raw is None:
        raise ConfigError("--cloudtrail-start and --cloudtrail-end must be given together")
    bounds: list[datetime] = []
    for flag, raw in (("--cloudtrail-start", start_raw), ("--cloudtrail-end", end_raw)):
        try:
            value = datetime.fromisoformat(raw)
        except ValueError as err:
            raise ConfigError(f"{flag} must be an ISO-8601 timestamp: {err}") from err
        if value.tzinfo is None:
            raise ConfigError(f"{flag} must carry a UTC offset, e.g. 2026-03-01T00:00:00+00:00")
        bounds.append(value)
    return bounds[0], bounds[1]


def _run_scan(config: RealityConfig, args: argparse.Namespace) -> None:
    """Wire the config into the scan orchestrator and run it.

    The AWS-side adapters are constructed only when the complete explicit
    opt-in triple is present; an explicit ``--aws`` with a missing piece is
    rejected rather than silently degraded to a local-only scan.
    """
    if config.aws_opt_in:
        config.require_aws()
    window = _cloudtrail_window(config, args)
    conn = connect(config.database_path)
    try:
        migrate(conn)
        store = ScanStore(conn)
        service = ScanService.from_config(config, store, cloudtrail_window=window)
        report = service.run(args.paths)
    finally:
        conn.close()
    _print_scan_report(report, config)


def _print_scan_report(report: ScanReport, config: RealityConfig) -> None:
    print(
        f"reality: scan {report.scan_run_id} complete; {len(report.sources)} source(s) considered"
    )
    for source in report.sources:
        print(f"  {source.source}: {source.status.value} - {source.detail}")
    written = (
        f"  wrote {report.resources} resource(s), {report.relationships} relationship(s), "
        f"{report.evidence} evidence item(s), and {report.coverage} coverage record(s)"
    )
    # Printed only when mappings exist, so the local-only demo output in the
    # README (a scan with no AWS side, hence no mappings) stays as documented.
    if report.identity_mappings:
        written += f", {report.identity_mappings} identity mapping(s)"
    print(f"{written} to {config.database_path}")


@contextmanager
def _read_store(config: RealityConfig) -> Iterator[ScanStore]:
    """Open the database for a read-only command.

    The file must already exist — these commands never create or migrate a
    database, because they never write. A missing database means no scan has
    run, which is a user error, not an empty result.
    """
    if not config.database_path.exists():
        raise ScanInputError(f"database not found: {config.database_path}; run reality scan first")
    conn = connect(config.database_path)
    try:
        yield ScanStore(conn)
    finally:
        conn.close()


@contextmanager
def _write_store(config: RealityConfig) -> Iterator[ScanStore]:
    """Open the database for a command that records its own conclusions.

    ``reconcile`` writes finding rows, so it needs a writable handle — but it
    still refuses to invent a database: the file must already exist, because
    reconciling nothing is an error rather than an empty result. Migrations are
    idempotent and only bring an older file up to the current schema.
    """
    if not config.database_path.exists():
        raise ScanInputError(f"database not found: {config.database_path}; run reality scan first")
    conn = connect(config.database_path)
    try:
        migrate(conn)
        yield ScanStore(conn)
    finally:
        conn.close()


def _run_reconcile(config: RealityConfig, args: argparse.Namespace) -> int:
    """Reconcile one scan run's candidates into stored findings."""
    with _write_store(config) as store:
        try:
            report = ReconcileService(store).run(args.scan_run)
        except ValueError as exc:
            # No discovery scan to analyse, or an unknown/reconciliation run.
            raise ScanInputError(str(exc)) from exc
    rendered = _render_output(report, args.output, "reconcile", args)
    return rendered


def _typed_values(resource: Resource) -> tuple[str, ...]:
    """The source-native identifiers a human would read off a plan or console.

    Deliberately excludes the display name: a name is not an identity, and
    matching on one is the guess this tool exists to refuse.
    """
    return tuple(
        value for value in (resource.terraform_address, resource.arn, resource.native_id) if value
    )


def _short_id_matches(canonical_id: str, query: str) -> bool:
    try:
        return parse_canonical(canonical_id).short_id() == query
    except Exception:
        return False


def _ambiguous(resource_id: str, hits: Sequence[Resource]) -> ScanInputError:
    return ScanInputError(
        f"{resource_id!r} matches {len(hits)} stored resources; "
        "use the full canonical ID: " + ", ".join(sorted(hit.canonical_id for hit in hits))
    )


def _resolve_resource_id(store: ScanStore, resource_id: str) -> str:
    """Resolve what the user typed to exactly one stored canonical ID.

    Accepted forms, tried in this order and never blended:

    1. a full canonical ID (six ``/``-separated segments);
    2. an exact Terraform address — ``aws_security_group.web_sg``;
    3. an exact ARN;
    4. an exact source-native ID — ``sg-0aaa111``;
    5. the short display form — ``terraform:aws/security_group.web_sg``;
    6. the same again, case-insensitively.

    Anything ambiguous is an error listing the candidates. Resolution never
    picks one of several matches, because picking one would be exactly the
    name-shaped guess this tool exists to refuse.
    """
    if resource_id.count("/") >= 5:
        return resource_id

    resources = store.resources.all()

    def first_unique(matches: list[Resource]) -> str | None:
        """The one canonical ID these matches denote, or None to try the next form."""
        if len(matches) == 1:
            return matches[0].canonical_id
        if len(matches) > 1:
            raise _ambiguous(resource_id, matches)
        return None

    for matches in (
        [r for r in resources if resource_id in _typed_values(r)],
        [r for r in resources if _short_id_matches(r.canonical_id, resource_id)],
    ):
        resolved = first_unique(matches)
        if resolved is not None:
            return resolved

    lowered = resource_id.lower()
    resolved = first_unique(
        [r for r in resources if lowered in {value.lower() for value in _typed_values(r)}]
    )
    return resolved if resolved is not None else resource_id


def _run_why(config: RealityConfig, args: argparse.Namespace) -> int:
    with _read_store(config) as store:
        resolved_id = _resolve_resource_id(store, args.resource)
        report = WhyService(store).explain(resolved_id)
    if report is None:
        raise ScanInputError(f"resource not found: {args.resource}; run reality scan first")
    rendered = _render_output(report, args.output, "why", args)
    return rendered


def _run_impact(config: RealityConfig, args: argparse.Namespace) -> int:
    with _read_store(config) as store:
        resolved_id = _resolve_resource_id(store, args.resource)
        report = ImpactService(store).blast_radius(resolved_id, depth=args.depth)
    if report is None:
        raise ScanInputError(f"resource not found: {args.resource}; run reality scan first")
    rendered = _render_output(report, args.output, "impact", args)
    if rendered != EXIT_OK:
        return rendered
    return _fail_on(report.risk, args.fail_on)


def _run_simulate(config: RealityConfig, args: argparse.Namespace) -> int:
    with _read_store(config) as store:
        report = SimulateService(store).run(args.plan_json, depth=args.depth)
    rendered = _render_output(report, args.output, "simulate", args)
    if rendered != EXIT_OK:
        return rendered
    return _fail_on(report.risk, args.fail_on)


def _fail_on(risk: RiskLevel, threshold: str) -> int:
    """Whether the caller's own risk threshold was met.

    The report has already been printed by the time this runs: the exit code
    carries the verdict, never the explanation. ``--fail-on never`` always
    succeeds, and an unresolved target (whose risk is unknown, not high) never
    trips a threshold.
    """
    floor = _FAIL_ON_BAND.get(threshold)
    if floor is None:
        return EXIT_OK
    return EXIT_POLICY if _SEVERITY[risk] >= _SEVERITY[floor] else EXIT_OK


def _render_output(
    report: WhyReport | ImpactReport | SimulateReport | ReconcileReport,
    output_format: str,
    command: str,
    args: argparse.Namespace,
) -> int:
    """Render a report in the specified output format.

    Returns the exit code to use: normally ``EXIT_OK``, or ``EXIT_USAGE`` when
    the requested format's optional dependency is not installed. Callers must
    propagate a non-OK result instead of continuing to their own exit logic, or
    a failed render would be reported as a successful command.

    ``output_format`` is a plain string, not an ``OutputFormat``: argparse
    yields ``str`` and the constants on that class are ``str`` values.
    """
    # --json flag takes precedence over --output
    if getattr(args, "json", False):
        output_format = OutputFormat.JSON

    try:
        if output_format == OutputFormat.JSON:
            print(stable_json(report))
        elif output_format == OutputFormat.YAML:
            _render_yaml(report, command)
        elif output_format == OutputFormat.CSV:
            _render_csv(report, command)
        elif output_format == OutputFormat.TABLE:
            _render_table(report, command)
        else:  # TEXT (default)
            _render_text(report, command)
    except MissingTableExtra as exc:
        # rich is an optional display dependency; report the fix instead of
        # letting an ImportError escape as a traceback.
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def _render_text(
    report: WhyReport | ImpactReport | SimulateReport | ReconcileReport, command: str
) -> None:
    """Render report as plain text (legacy format)."""
    if command == "why":
        sys.stdout.write(render_why(cast(WhyReport, report)))
    elif command == "impact":
        sys.stdout.write(render_impact(cast(ImpactReport, report)))
    elif command == "simulate":
        sys.stdout.write(render_simulate(cast(SimulateReport, report)))
    elif command == "reconcile":
        sys.stdout.write(render_reconcile(cast(ReconcileReport, report)))


def _render_table(
    report: WhyReport | ImpactReport | SimulateReport | ReconcileReport, command: str
) -> None:
    """Render report as a rich table."""
    if command == "why":
        render_why_table(cast(WhyReport, report))
    elif command == "impact":
        render_impact_table(cast(ImpactReport, report))
    elif command == "simulate":
        render_simulate_table(cast(SimulateReport, report))
    elif command == "reconcile":
        render_reconcile_table(cast(ReconcileReport, report))


def _render_yaml(
    report: WhyReport | ImpactReport | SimulateReport | ReconcileReport, command: str
) -> None:
    """Render report as YAML."""
    if command == "why":
        print(render_why_yaml(cast(WhyReport, report)))
    elif command == "impact":
        print(render_impact_yaml(cast(ImpactReport, report)))
    elif command == "simulate":
        print(render_simulate_yaml(cast(SimulateReport, report)))
    elif command == "reconcile":
        print(render_reconcile_yaml(cast(ReconcileReport, report)))


def _render_csv(
    report: WhyReport | ImpactReport | SimulateReport | ReconcileReport, command: str
) -> None:
    """Render report as CSV."""
    if command == "why":
        print(render_why_csv(cast(WhyReport, report)))
    elif command == "impact":
        print(render_impact_csv(cast(ImpactReport, report)))
    elif command == "simulate":
        print(render_simulate_csv(cast(SimulateReport, report)))
    elif command == "reconcile":
        print(render_reconcile_csv(cast(ReconcileReport, report)))


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code, never raises for expected errors."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        config = RealityConfig(
            database_path=args.database,
            aws_opt_in=args.aws,
            aws_profile=args.profile,
            aws_region=args.region,
        )
        config.validate_aws_flags()
        return _dispatch(args.command, config, args)
    except ConfigError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ScanInputError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except CommandNotImplemented as exc:
        print(f"reality: {exc}", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
