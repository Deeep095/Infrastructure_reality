"""Build the offline demo database used by the README walkthrough.

The demo needs *both* worlds at once: what Terraform declares and what AWS
reports. Reaching the AWS side for real would mean credentials, a network
call, and an account — none of which belong in a README. So this script
replays the recorded API responses already committed under
``tests/fixtures/`` through the same ``client_factory`` seam the test suite
uses. Nothing here talks to AWS: the responses are read off disk, exactly as
``terraform show -json`` is read off disk.

What the resulting world contains, and why each part matters:

* ``aws_security_group.web_sg`` is declared *and* observed, and the declared
  database's attachment to it joins the observed one through the ARN in the
  state — a ``confirmed`` conclusion that required an identity mapping, not a
  name match.
* The observed web instance also attaches to ``sg-0zzz999``, which no state
  resource declares and no mapping can reach — an ``undocumented`` conclusion.
  This is the headline: a live dependency Terraform does not account for.
* ``processor_role`` holds a policy allowing an S3 bucket with no CloudTrail
  usage behind it — a ``possible`` conclusion, distinct from both of the above.
* Edges that only one world has stay ``declared_only``, which is not a verdict
  about risk: it says the other world was never consulted about them, so
  ``unknown`` is the honest reading and no conclusion of confidence is claimed.

Every conclusion in the report is listed, so the counts below always add up to
the number of findings.

Usage::

    python scripts/build_demo_db.py            # writes ./demo.db
    python scripts/build_demo_db.py --out other.db

The file is plain SQLite and nothing else is written; delete it when done.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from reality.config import RealityConfig  # noqa: E402
from reality.domain.enums import Conclusion  # noqa: E402
from reality.services.reconcile import ReconcileService  # noqa: E402
from reality.services.scan import ScanService  # noqa: E402
from reality.storage.migrations import migrate  # noqa: E402
from reality.storage.repositories import ScanStore  # noqa: E402
from reality.storage.sqlite import connect  # noqa: E402

TESTS = REPO / "tests"
AWS_FIXTURES = TESTS / "fixtures" / "aws"
IAM_FIXTURES = TESTS / "fixtures" / "iam"
CLOUDTRAIL_FIXTURES = TESTS / "fixtures" / "cloudtrail"
TF_STATE = TESTS / "fixtures" / "terraform" / "state.json"

PROFILE = "demo"
REGION = "eu-west-1"
START = datetime(2026, 3, 1, 0, 0, tzinfo=UTC)
END = datetime(2026, 3, 2, 0, 0, tzinfo=UTC)

#: The complete set of operations the four adapters may ever issue. A replay
#: client refuses anything else, so the demo cannot drift into a call the
#: safety contract forbids.
ALLOWED_OPERATIONS = frozenset(
    {
        "get_caller_identity",
        "describe_instances",
        "describe_security_groups",
        "list_functions",
        "describe_db_instances",
        "list_buckets",
        "list_roles",
        "list_role_policies",
        "get_role_policy",
        "list_attached_role_policies",
        "get_policy",
        "get_policy_version",
        "lookup_events",
    }
)


class ReplayClient:
    """A boto3-shaped client that returns recorded responses from disk."""

    def __init__(self, service: str, script: dict[str, list[Any]]) -> None:
        self.service = service
        self._script = script
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str) -> Any:
        if operation.startswith("_"):
            raise AttributeError(operation)

        def _call(**kwargs: Any) -> Any:
            if operation not in ALLOWED_OPERATIONS:
                raise AssertionError(
                    f"{self.service}.{operation} is not an allowed read-only operation"
                )
            self.calls.append((operation, dict(kwargs)))
            queue = self._script.get(operation, [])
            if not queue:
                raise AssertionError(
                    f"{self.service}.{operation} was called more times than the "
                    "recorded responses cover"
                )
            outcome = queue.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return _call


class ReplayClientFactory:
    """Hands out one recorded client per AWS service."""

    def __init__(self, script: dict[str, dict[str, list[Any]]]) -> None:
        self._script = script
        self.clients: dict[str, ReplayClient] = {}

    def __call__(self, service: str) -> ReplayClient:
        if service not in self.clients:
            self.clients[service] = ReplayClient(service, self._script.get(service, {}))
        return self.clients[service]


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def recorded_script() -> dict[str, dict[str, list[Any]]]:
    """Every recorded response the demo scan replays, keyed by service."""
    return {
        "sts": {"get_caller_identity": [load(AWS_FIXTURES / "get_caller_identity.json")]},
        "ec2": {
            "describe_instances": list(load(AWS_FIXTURES / "describe_instances.json")["pages"]),
            "describe_security_groups": list(
                load(AWS_FIXTURES / "describe_security_groups.json")["pages"]
            ),
        },
        "lambda": {"list_functions": list(load(AWS_FIXTURES / "list_functions.json")["pages"])},
        "rds": {
            "describe_db_instances": list(
                load(AWS_FIXTURES / "describe_db_instances.json")["pages"]
            )
        },
        "s3": {"list_buckets": [load(AWS_FIXTURES / "list_buckets.json")]},
        "iam": {
            "list_roles": list(load(IAM_FIXTURES / "list_roles.json")["pages"]),
            "list_role_policies": [
                *load(IAM_FIXTURES / "list_role_policies_processor.json")["pages"],
                load(IAM_FIXTURES / "list_role_policies_cleanup.json"),
                load(IAM_FIXTURES / "list_role_policies_auditor.json"),
            ],
            "get_role_policy": [
                load(IAM_FIXTURES / "get_role_policy_processor_inline.json"),
                load(IAM_FIXTURES / "get_role_policy_processor_readonly.json"),
                load(IAM_FIXTURES / "get_role_policy_cleanup_inline.json"),
                load(IAM_FIXTURES / "get_role_policy_auditor_inline.json"),
            ],
            "list_attached_role_policies": [
                load(IAM_FIXTURES / "list_attached_role_policies_processor.json"),
                load(IAM_FIXTURES / "list_attached_role_policies_cleanup.json"),
                load(IAM_FIXTURES / "list_attached_role_policies_auditor.json"),
            ],
            "get_policy": [
                load(IAM_FIXTURES / "get_policy_data_reader.json"),
                load(IAM_FIXTURES / "get_policy_auditor_access.json"),
            ],
            "get_policy_version": [
                load(IAM_FIXTURES / "get_policy_version_data_reader_v2.json"),
                load(IAM_FIXTURES / "get_policy_version_auditor_access_v1.json"),
            ],
        },
        "cloudtrail": {
            "lookup_events": list(load(CLOUDTRAIL_FIXTURES / "lookup_events.json")["pages"])
        },
    }


def build(database: Path) -> tuple[Any, Any]:
    """Scan the recorded world and reconcile it. Returns the scan and reconcile reports.

    The database is rebuilt from scratch so the demo can never show a
    conclusion left over from an earlier run. The connection is closed before
    returning: the file on disk is the whole result.
    """
    if database.exists():
        database.unlink()
    conn = connect(database)
    try:
        migrate(conn)
        store = ScanStore(conn)
        config = RealityConfig(
            database_path=database,
            aws_opt_in=True,
            aws_profile=PROFILE,
            aws_region=REGION,
        )
        factory = ReplayClientFactory(recorded_script())
        scan = ScanService.from_config(
            config, store, cloudtrail_window=(START, END), client_factory=factory
        ).run([TF_STATE])
        report = ReconcileService(store).run()
    finally:
        conn.close()
    return scan, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_demo_db",
        description=(
            "Build the offline demo database from recorded API responses. "
            "No AWS credentials, no network, no Terraform executable."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO / "demo.db",
        help="database file to write (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    scan, report = build(args.out)

    print(f"demo: wrote {args.out} from recorded responses (no AWS call was made)")
    print(
        f"  scan {scan.scan_run_id}: {scan.resources} resource(s), "
        f"{scan.relationships} relationship(s)"
    )
    # Counted off report.counts, not by filtering the findings here, so a
    # conclusion added later cannot silently drop out of this summary.
    tally = " ".join(
        f"{conclusion.value} {report.counts.get(conclusion.value, 0)}" for conclusion in Conclusion
    )
    print(f"  reconcile pass {report.scan_run_id}: {len(report.findings)} finding(s) - {tally}")
    for item in report.findings:
        if item.conclusion is not Conclusion.UNDOCUMENTED:
            continue
        print(f"  undocumented: {item.source_canonical_id} -> {item.target_canonical_id}")
    print()
    print("  next: python -m reality --database demo.db reconcile")
    print("        python -m reality --database demo.db why <resource>")
    print("        python -m reality --database demo.db impact <resource>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
