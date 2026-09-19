"""Command-line interface for reality.

``scan`` runs the orchestrator from :mod:`reality.services.scan` (local
Terraform JSON paths, plus the opted-in AWS/IAM/CloudTrail sources).
``why``/``impact``/``simulate`` are read-only reports from the stored
database: they open it without migrating or writing, and ``simulate`` parses
a local plan JSON without ever running Terraform or contacting AWS. Only
``reconcile`` still reports a clear "not implemented" status.

Exit codes:
    0  success
    2  usage error (argparse)
    3  command registered but not implemented yet
    4  configuration rejected by the safety contract
    5  invalid local input (a scan or simulation refused before writing
       anything, or a resource the database has never seen)
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from reality.config import ConfigError, RealityConfig
from reality.services.impact import DEFAULT_DEPTH, ImpactService, SimulateService
from reality.services.reports import (
    WhyService,
    render_impact,
    render_simulate,
    render_why,
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


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser. Flags before the subcommand apply globally."""
    parser = argparse.ArgumentParser(
        prog="reality",
        description=(
            "Read-only cloud infrastructure discovery and local blast-radius "
            "simulation. Never applies, destroys, or refreshes infrastructure."
        ),
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=RealityConfig().database_path,
        help="local SQLite database file (default: %(default)s)",
    )
    aws = parser.add_argument_group("AWS opt-in (all three required together, no defaults)")
    aws.add_argument(
        "--aws",
        action="store_true",
        help="explicitly allow read-only AWS calls",
    )
    aws.add_argument("--profile", help="named AWS profile; required with --aws")
    aws.add_argument("--region", help="AWS region; required with --aws")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser(
        "scan",
        help="discover resources from selected sources into the local database",
    )
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
    sub.add_parser(
        "reconcile",
        help="compare declared (Terraform) and observed (AWS) state",
    )
    why = sub.add_parser("why", help="explain why a resource exists (evidence and conclusions)")
    why.add_argument("resource", help="canonical resource ID")
    impact = sub.add_parser("impact", help="report the blast radius of a resource")
    impact.add_argument("resource", help="canonical resource ID")
    impact.add_argument(
        "--depth",
        type=_positive_int,
        default=DEFAULT_DEPTH,
        help="maximum traversal depth for dependents (default: %(default)s)",
    )
    impact.add_argument("--json", action="store_true", help="print the report as stable JSON")
    simulate = sub.add_parser(
        "simulate",
        help="compute blast radius from an exported Terraform plan JSON (never applies it)",
    )
    simulate.add_argument("plan_json", help="path to a `terraform show -json` plan file")
    simulate.add_argument(
        "--depth",
        type=_positive_int,
        default=DEFAULT_DEPTH,
        help="maximum traversal depth per target (default: %(default)s)",
    )
    simulate.add_argument("--json", action="store_true", help="print the report as stable JSON")

    return parser


def _dispatch(command: str, config: RealityConfig, args: argparse.Namespace) -> None:
    """Run a command. Commands not yet delivered raise CommandNotImplemented."""
    if command == "scan":
        _run_scan(config, args)
    elif command == "reconcile":
        raise CommandNotImplemented("reality reconcile is not implemented yet")
    elif command == "why":
        _run_why(config, args)
    elif command == "impact":
        _run_impact(config, args)
    elif command == "simulate":
        _run_simulate(config, args)


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


def _run_why(config: RealityConfig, args: argparse.Namespace) -> None:
    with _read_store(config) as store:
        report = WhyService(store).explain(args.resource)
    if report is None:
        raise ScanInputError(f"resource not found: {args.resource}; run reality scan first")
    sys.stdout.write(render_why(report))


def _run_impact(config: RealityConfig, args: argparse.Namespace) -> None:
    with _read_store(config) as store:
        report = ImpactService(store).blast_radius(args.resource, depth=args.depth)
    if report is None:
        raise ScanInputError(f"resource not found: {args.resource}; run reality scan first")
    if args.json:
        print(stable_json(report))
    else:
        sys.stdout.write(render_impact(report))


def _run_simulate(config: RealityConfig, args: argparse.Namespace) -> None:
    with _read_store(config) as store:
        report = SimulateService(store).run(args.plan_json, depth=args.depth)
    if args.json:
        print(stable_json(report))
    else:
        sys.stdout.write(render_simulate(report))


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
        _dispatch(args.command, config, args)
    except ConfigError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ScanInputError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except CommandNotImplemented as exc:
        print(f"reality: {exc}", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    return EXIT_OK
