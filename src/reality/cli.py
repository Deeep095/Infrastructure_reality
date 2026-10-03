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

from reality import __version__
from reality.config import ConfigError, RealityConfig
from reality.domain.ids import parse_canonical
from reality.domain.models import Resource
from reality.services.doctor import render_doctor, run_doctor
from reality.services.graph import GraphView
from reality.services.impact import (
    DEFAULT_DEPTH,
    Assessment,
    ImpactReport,
    ImpactService,
    RiskLevel,
    SimulateReport,
    SimulateService,
)
from reality.services.progress import (
    Cancelled as ScanCancelled,
)
from reality.services.progress import (
    ProgressReporter,
    reporter_for_interactive,
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
from reality.settings import (
    ENV_DATABASE,
    ENV_PROFILE,
    ENV_REGION,
    ResolvedSetting,
    SettingsError,
    UserSettings,
    config_path,
    load_settings,
    resolve_setting,
    save_settings,
)
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3
EXIT_CONFIG = 4
EXIT_INPUT = 5
EXIT_POLICY = 6
#: A scan the operator stopped. Distinct from failure: nothing is wrong, the
#: work simply did not finish, and the database was left unchanged.
EXIT_INTERRUPTED = 130
#: `reality doctor` found at least one failed check. Warnings and skipped
#: optional extras still exit 0, because both leave the tool usable.
EXIT_UNHEALTHY = 1


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

    The global parser also uses ``SUPPRESS`` for ``--database``, ``--profile``
    and ``--region`` so that "the user did not pass this" stays
    distinguishable from "this is the default". Without that distinction the
    settings file and the environment could never supply a value, because
    argparse would have already filled in the built-in default.
    """
    parser.add_argument(
        "--database",
        type=Path,
        default=argparse.SUPPRESS,
        help="local SQLite database file (default: reality.db, or the config file)",
    )
    parser.add_argument(
        "--aws",
        action="store_true",
        default=False if global_defaults else argparse.SUPPRESS,
        help="explicitly allow read-only AWS calls",
    )
    parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="named AWS profile; required with --aws",
    )
    parser.add_argument(
        "--region",
        default=argparse.SUPPRESS,
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
    parser.add_argument(
        "--version",
        action="version",
        version=f"reality {__version__}",
        help="print the installed version and exit",
    )
    _add_common_flags(parser, global_defaults=True)

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    doctor = sub.add_parser(
        "doctor",
        help="check this machine: python, extras, config, database, and (opt-in) AWS",
    )
    _add_common_flags(doctor, global_defaults=False)

    config_cmd = sub.add_parser(
        "config",
        help="show or edit the settings file used for defaults",
    )
    _add_common_flags(config_cmd, global_defaults=False)
    config_cmd.add_argument(
        "action",
        nargs="?",
        choices=("show", "path", "init"),
        default="show",
        help="show the effective settings (default), print the file's path, or write it",
    )
    config_cmd.add_argument(
        "--set-database",
        metavar="PATH",
        help="with 'init': persist this database path",
    )
    config_cmd.add_argument(
        "--set-profile",
        metavar="NAME",
        help="with 'init': persist this AWS profile name",
    )
    config_cmd.add_argument(
        "--set-region",
        metavar="NAME",
        help="with 'init': persist this AWS region",
    )

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
    rec.add_argument(
        "--verbose",
        action="store_true",
        help="show full finding details instead of summary",
    )
    rec.add_argument(
        "--fail-on",
        choices=("never", "confirmed", "undocumented", "possible", "declared_only", "unknown"),
        default="never",
        help=(
            "exit 6 when findings of this conclusion or worse are present; "
            "order is confirmed < undocumented < possible < declared_only < unknown "
            "(default: %(default)s)"
        ),
    )
    rec.add_argument(
        "--conclusion",
        choices=("confirmed", "undocumented", "possible", "declared_only", "unknown"),
        help="filter output to only findings with this conclusion",
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

    graph = sub.add_parser(
        "graph",
        help="export a subgraph of the stored relationships as DOT, Mermaid, or text",
    )
    _add_common_flags(graph, global_defaults=False)
    graph.add_argument("resource", help="canonical ID, Terraform address, ARN, or native ID")
    graph.add_argument(
        "--depth",
        type=_positive_int,
        default=DEFAULT_DEPTH,
        help="maximum traversal depth (default: %(default)s)",
    )
    graph.add_argument(
        "--output",
        choices=("text", "dot", "mermaid"),
        default="dot",
        help="output format (default: %(default)s)",
    )
    graph.add_argument(
        "--direction",
        choices=("incoming", "outgoing"),
        default="incoming",
        help="traverse incoming edges (dependents/blast radius) or outgoing (dependencies)",
    )
    graph.add_argument(
        "--include-unresolved",
        action="store_true",
        help="include unresolved/-/-/- nodes in the export",
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
    simulate.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help=(
            f"also exit {EXIT_POLICY} when any destructive target could not be "
            "assessed; a plan whose targets are unresolved is inconclusive, "
            "not safe"
        ),
    )

    return parser


def _flag(args: argparse.Namespace, name: str) -> str | Path | None:
    """The raw flag value, or ``None`` if the user did not pass it.

    Not every common flag is a string: ``--database`` is parsed to a ``Path``
    and the shared parser lets the subparser override the global value, so the
    resolved value can be either. Returning ``None`` only for a genuinely
    absent flag is what keeps a supplied value from being silently dropped.
    """
    value = getattr(args, name, None)
    if value is None or value == "":
        return None
    if isinstance(value, (str, Path)):
        return value
    return str(value)


def _string_flag(args: argparse.Namespace, name: str) -> str | None:
    """A flag known to be a plain string (profile, region)."""
    value = _flag(args, name)
    return value if isinstance(value, str) else None


def _resolve_aws(
    args: argparse.Namespace, settings: UserSettings
) -> tuple[ResolvedSetting, ResolvedSetting]:
    """The AWS profile and region, each with where it came from."""
    profile = resolve_setting(
        _string_flag(args, "profile"),
        env_name=ENV_PROFILE,
        file_value=settings.profile,
        default=None,
    )
    region = resolve_setting(
        _string_flag(args, "region"),
        env_name=ENV_REGION,
        file_value=settings.region,
        default=None,
    )
    return profile, region


def _aws_origin_note(args: argparse.Namespace, settings: UserSettings) -> str | None:
    """A note naming the account context an AWS read is about to use.

    Returned only when at least one half of the triple came from somewhere
    other than the command line. A saved profile is a convenience, but it means
    ``--aws`` alone can read an account the command line never names, so the
    run states which one it resolved and from where. When the user typed both
    values there is nothing to disclose - they are already on screen.
    """
    profile, region = _resolve_aws(args, settings)
    if profile.source == "command line" and region.source == "command line":
        return None
    return (
        f"reality: reading AWS as profile {profile.value!r} [{profile.source}], "
        f"region {region.value!r} [{region.source}]"
    )


def _build_config(args: argparse.Namespace, settings: UserSettings) -> RealityConfig:
    """Resolve the runtime config from flags, environment, file, then default.

    Precedence is fixed and documented in :mod:`reality.settings`. The one
    thing that never comes from the file is the AWS opt-in: ``--aws`` is a
    per-invocation decision, so ``aws_opt_in`` reads only the flag.
    """
    database_flag = _flag(args, "database")
    database = resolve_setting(
        str(database_flag) if isinstance(database_flag, Path) else database_flag,
        env_name=ENV_DATABASE,
        file_value=settings.database,
        default="reality.db",
    )
    profile, region = _resolve_aws(args, settings)
    # The database always resolves: it has a built-in default, unlike the AWS
    # profile and region, which stay absent until something supplies them.
    if database.value is None:  # pragma: no cover - a default is always given
        raise SettingsError("no database path resolved")
    return RealityConfig(
        database_path=Path(database.value),
        aws_opt_in=bool(getattr(args, "aws", False)),
        aws_profile=profile.value,
        aws_region=region.value,
    )


def _run_doctor(config: RealityConfig) -> int:
    """Report on the environment and return 0 or 1."""
    report = run_doctor(config)
    sys.stdout.write(render_doctor(report))
    return EXIT_OK if report.healthy else EXIT_UNHEALTHY


def _run_config(args: argparse.Namespace) -> int:
    """Show the effective settings, or print/write the settings file."""
    path = config_path()
    if args.action == "path":
        print(path)
        return EXIT_OK

    try:
        settings, path = load_settings(path)
    except SettingsError as err:
        print(f"reality: error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    if args.action == "init":
        given = (args.set_database, args.set_profile, args.set_region)
        if not any(value is not None for value in given):
            print(
                "reality: nothing to write; pass --set-database, --set-profile, "
                "or --set-region (e.g. reality config init --set-profile default "
                "--set-region eu-west-1)"
            )
            return EXIT_USAGE
        merged = UserSettings(
            database=args.set_database or settings.database,
            profile=args.set_profile or settings.profile,
            region=args.set_region or settings.region,
        )
        written = save_settings(merged, path)
        print(f"reality: wrote {written}")
        return EXIT_OK

    # "show": the effective values *and* where each came from, so "why is my
    # region eu-west-1?" is answerable without reading three files.
    env = {
        "database": ENV_DATABASE,
        "profile": ENV_PROFILE,
        "region": ENV_REGION,
    }
    defaults = {"database": "reality.db", "profile": None, "region": None}
    print(f"reality: settings file: {path}")
    if not path.is_file():
        print("  (none; built-in defaults apply)")
    for field in ("database", "profile", "region"):
        resolved = resolve_setting(
            # The real flag, so `config --region X show` answers "what would X
            # win with?" without the reader having to know the precedence rules.
            _string_flag(args, field),
            env_name=env[field],
            file_value=getattr(settings, field),
            default=defaults[field],
        )
        shown = resolved.value if resolved.value is not None else "(none)"
        print(f"  {field:<9} {shown}  [{resolved.source}]")
    print("  aws opt-in is never persisted; every AWS read needs --aws on the command line")
    return EXIT_OK


def _dispatch(
    command: str, config: RealityConfig, args: argparse.Namespace, settings: UserSettings
) -> int:
    """Run a command and return its exit code."""
    if command == "doctor":
        return _run_doctor(config)
    if command == "config":
        return _run_config(args)
    if command == "scan":
        _run_scan(config, args, settings)
    elif command == "reconcile":
        return _run_reconcile(config, args)
    elif command == "why":
        _run_why(config, args)
    elif command == "impact":
        return _run_impact(config, args)
    elif command == "graph":
        return _run_graph(config, args)
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


def _progress_reporter() -> ProgressReporter:
    """The progress indicator this terminal can support.

    Silent when stderr is redirected, so a piped log gets the report and
    nothing else. There is deliberately no flag to force it on: progress that
    a user cannot see the terminal state of is noise in their log, and they
    can always redirect stderr away from a terminal.
    """
    return reporter_for_interactive()


def _run_scan(config: RealityConfig, args: argparse.Namespace, settings: UserSettings) -> None:
    """Wire the config into the scan orchestrator and run it.

    The AWS-side adapters are constructed only when the complete explicit
    opt-in triple is present; an explicit ``--aws`` with a missing piece is
    rejected rather than silently degraded to a local-only scan.
    """
    if config.aws_opt_in:
        config.require_aws()
        # Stderr, so a redirected report stays machine-readable. Printed before
        # the first call, because "which account did this read?" is not a
        # question to answer after the fact.
        note = _aws_origin_note(args, settings)
        if note is not None:
            print(note, file=sys.stderr)
    window = _cloudtrail_window(config, args)
    conn = connect(config.database_path)
    try:
        migrate(conn)
        store = ScanStore(conn)
        service = ScanService.from_config(
            config, store, cloudtrail_window=window, progress=_progress_reporter()
        )
        report = service.run(args.paths)
    except (KeyboardInterrupt, ScanCancelled) as err:
        # The scan writes one transaction at the end, so stopping here leaves
        # the database exactly as it was: no partial run, no half-written rows.
        reason = "cancelled" if isinstance(err, ScanCancelled) else "interrupted"
        raise ScanCancelled(f"scan {reason}") from err
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
        # Filter by conclusion if requested.
        if args.conclusion is not None:
            report = report.filter_conclusion(args.conclusion)
        # Apply --fail-on gate (based on conclusion severity order).
        fail_code = _fail_on_conclusion(report, args.fail_on)
        rendered = _render_output(report, args.output, "reconcile", args)
        return fail_code if fail_code else rendered


def _fail_on_conclusion(report: ReconcileReport, threshold: str) -> int:
    """Return exit code 6 if any finding meets or exceeds the conclusion threshold.

    Severity order: confirmed < undocumented < possible < declared_only < unknown.
    """
    if threshold == "never":
        return EXIT_OK
    order = ("confirmed", "undocumented", "possible", "declared_only", "unknown")
    threshold_idx = order.index(threshold)
    for finding in report.findings:
        if finding.conclusion in order[: threshold_idx + 1]:
            return EXIT_POLICY
    return EXIT_OK


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


def _run_graph(config: RealityConfig, args: argparse.Namespace) -> int:
    """Export a subgraph as DOT, Mermaid, or text."""
    with _read_store(config) as store:
        discovery_run_id = store.scan_runs.latest_discovery_run()
        if discovery_run_id is None:
            raise ScanInputError("no discovery scan runs found; run 'reality scan' first")
        # Findings are stored in the reconciliation scan run, not the discovery run.
        reconciliation_run_id = store.scan_runs.latest_reconciliation_run()
        view = GraphView(store, discovery_run_id, findings_scan_run_id=reconciliation_run_id)
        resolved = view.resolve_subject(args.resource)
        if resolved is None:
            raise ScanInputError(f"resource not found: {args.resource}")
        output = view.export_graph(
            resolved,
            depth=args.depth,
            direction=args.direction,
            include_unresolved=args.include_unresolved,
            output_format=args.output,
        )
    print(output)
    return EXIT_OK


def _run_simulate(config: RealityConfig, args: argparse.Namespace) -> int:
    with _read_store(config) as store:
        report = SimulateService(store).run(args.plan_json, depth=args.depth)
    rendered = _render_output(report, args.output, "simulate", args)
    if rendered != EXIT_OK:
        return rendered
    # An inconclusive assessment is a verdict of its own: a plan whose targets
    # could not be resolved is not safe to proceed on, whatever the known risk.
    if args.fail_on_unknown and report.assessment is not Assessment.COMPLETE:
        return EXIT_POLICY
    return _fail_on(report.risk, args.fail_on)


def _fail_on(risk: RiskLevel | None, threshold: str) -> int:
    """Whether the caller's own risk threshold was met.

    The report has already been printed by the time this runs: the exit code
    carries the verdict, never the explanation. ``--fail-on never`` always
    succeeds, and an unknown risk (``None``) never trips a threshold — absence
    of a computed risk is not a low one.
    """
    if risk is None:
        return EXIT_OK
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

    # Auto-select table format when rich is installed and stdout is a TTY.
    # This gives users a nicer default without forcing a flag, while keeping
    # piped/CI output as raw text.
    if output_format == OutputFormat.TEXT:
        try:
            import shutil

            from rich.console import Console
        except ImportError:
            pass
        else:
            if shutil.get_terminal_size().columns > 80:
                console = Console()
                if console.is_terminal:
                    output_format = OutputFormat.TABLE

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
            _render_text(report, command, bool(getattr(args, "verbose", False)))
    except MissingTableExtra as exc:
        # rich is an optional display dependency; report the fix instead of
        # letting an ImportError escape as a traceback.
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def _render_text(
    report: WhyReport | ImpactReport | SimulateReport | ReconcileReport,
    command: str,
    verbose: bool = False,
) -> None:
    """Render report as plain text (legacy format).

    ``verbose`` is only meaningful for ``reconcile``, whose default text output
    is a summary; every other report already renders in full.
    """
    if command == "why":
        sys.stdout.write(render_why(cast(WhyReport, report)))
    elif command == "impact":
        sys.stdout.write(render_impact(cast(ImpactReport, report)))
    elif command == "simulate":
        sys.stdout.write(render_simulate(cast(SimulateReport, report)))
    elif command == "reconcile":
        sys.stdout.write(render_reconcile(cast(ReconcileReport, report), verbose=verbose))


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
        try:
            settings, _ = load_settings()
        except SettingsError:
            # `doctor` is the command you run *because* something is broken, so
            # it must survive a settings file it cannot parse and report the
            # problem as one failed check. Every other command refuses, because
            # silently ignoring a file the user wrote is how a typo turns into
            # a run that used the wrong defaults without anyone noticing.
            if args.command != "doctor":
                raise
            settings = UserSettings()
        config = _build_config(args, settings)
        # Only explicitly typed flags are policed; a saved profile or region is
        # a preference, not a request to read AWS. `config` is exempt entirely:
        # inspecting what a flag *would* resolve to is the whole point of it.
        if args.command != "config":
            config.validate_aws_flags(
                flag_profile=_string_flag(args, "profile"),
                flag_region=_string_flag(args, "region"),
            )
        return _dispatch(args.command, config, args, settings)
    except SettingsError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ConfigError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ScanInputError as exc:
        print(f"reality: error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except ScanCancelled as exc:
        # A cancelled or interrupted scan wrote nothing: the scan is a single
        # transaction, so an operator who stops it is not left with a partial
        # run to reason about.
        print(f"reality: {exc}; nothing was written", file=sys.stderr)
        return EXIT_INTERRUPTED
    except CommandNotImplemented as exc:
        print(f"reality: {exc}", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
