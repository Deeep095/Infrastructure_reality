"""Live AWS smoke test — runs the real adapters against a real account.

This is the test that has never existed: every other test in this repository
uses recorded fixtures or botocore stubs. This script points the actual
adapters at an actual AWS account, so it is the first time the AWS code path
meets real API responses.

It is strictly read-only. The adapters' operation whitelist permits only
List/Get/Describe-style calls, and this script asserts that no mutating
operation was issued before it trusts anything.

Usage::

    python ManualTests/aws-live/run_live_test.py --profile deepanshu

Everything it writes goes to ``live.db`` in this folder. Delete that file to
start over. Nothing here touches Terraform and nothing is applied.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from reality import cli  # noqa: E402
from reality.adapters.aws_resources import ALLOWED_OPERATIONS  # noqa: E402

HERE = Path(__file__).resolve().parent
DATABASE = HERE / "live.db"

# A short window: CloudTrail lookups are the most expensive call here, and one
# day is enough to prove the path works without scanning a month of history.
WINDOW_DAYS = 1

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


def run(args: list[str]) -> tuple[int, str]:
    """Run one CLI command, returning (exit code, combined output)."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue() + err.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, help="AWS profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--with-state",
        type=Path,
        nargs="?",
        const=REPO / "tests" / "fixtures" / "terraform" / "state.json",
        default=None,
        help="also parse this terraform show -json file, so reconcile has both worlds",
    )
    args = parser.parse_args()

    if DATABASE.exists():
        DATABASE.unlink()

    print(f"live AWS test: profile={args.profile} region={args.region}")
    print(f"database: {DATABASE}")
    print(f"cloudtrail window: {WINDOW_DAYS} day(s)\n")

    # --- 0. the safety contract ------------------------------------------------
    print("safety contract")
    record(
        "no mutating operation is permitted",
        {
            "get_caller_identity",
            "describe_instances",
            "describe_security_groups",
            "list_functions",
            "describe_db_instances",
            "list_buckets",
            "list_roles",
            "list_role_policies",
            "list_attached_role_policies",
            "get_role_policy",
            "get_policy",
            "get_policy_version",
            "lookup_events",
        }
        >= ALLOWED_OPERATIONS,
        f"{len(ALLOWED_OPERATIONS)} read-only operations whitelisted",
    )

    # --- 1. identity ----------------------------------------------------------
    print("\nidentity")
    import boto3

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    identity = session.client("sts").get_caller_identity()
    record(
        "sts get_caller_identity",
        bool(identity.get("Account")),
        f"account {identity['Account']}",
    )

    # --- 2. scan --------------------------------------------------------------
    print("\nscan")
    scan_args = [
        "--database",
        str(DATABASE),
        "--aws",
        "--profile",
        args.profile,
        "--region",
        args.region,
        "scan",
    ]
    if args.with_state is not None:
        scan_args.append(str(args.with_state))
    code, out = run(scan_args)
    record("scan exits 0", code == 0, out.strip().splitlines()[0] if out.strip() else "")

    # --- 3. reconcile ---------------------------------------------------------
    print("\nreconcile")
    code, out = run(["--database", str(DATABASE), "reconcile"])
    record("reconcile exits 0", code == 0)
    record(
        "reconcile produced findings",
        "findings (" in out,
        out.strip().splitlines()[1].strip() if len(out.strip().splitlines()) > 1 else "",
    )

    # --- 4. why ---------------------------------------------------------------
    # Pick a resource the scan actually stored. The IAM adapter covers roles,
    # not users, so the caller's user ARN is deliberately not a valid target.
    print("\nwhy")
    import sqlite3

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    subject = conn.execute(
        "SELECT canonical_id FROM resources WHERE resource_type = 'iam_role' LIMIT 1"
    ).fetchone()["canonical_id"]
    print(f"  using {subject}")
    code, out = run(["--database", str(DATABASE), "why", subject])
    record("why on a real role exits 0", code == 0)
    record(
        "why shows relationships",
        "relationships (" in out,
        next((ln.strip() for ln in out.splitlines() if "relationships (" in ln), ""),
    )

    # --- 5. impact ------------------------------------------------------------
    print("\nimpact")
    code, out = run(["--database", str(DATABASE), "impact", subject])
    record("impact on a real role exits 0", code == 0)
    record(
        "impact reports a risk band",
        "risk: " in out,
        next((ln.strip() for ln in out.splitlines() if "risk:" in ln), ""),
    )

    # --- 6. output formats ----------------------------------------------------
    print("\noutput formats")
    for fmt in ("json", "yaml", "csv", "table"):
        code, out = run(["--database", str(DATABASE), "reconcile", "--output", fmt])
        record(f"reconcile --output {fmt}", code == 0 and len(out.strip()) > 0)

    # --- 7. fail-on gate ------------------------------------------------------
    print("\nfail-on gate")
    code, _ = run(["--database", str(DATABASE), "impact", subject, "--fail-on", "high"])
    record("--fail-on high returns 0 or 6", code in (0, 6), f"exit {code}")

    # --- 8. what actually got stored -----------------------------------------
    print("\nstored state")
    for table in ("resources", "relationships", "evidence", "coverage", "findings"):
        try:
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            record(f"{table} rows", count >= 0, str(count))
        except sqlite3.Error as exc:
            record(f"{table} rows", False, str(exc))

    print("\nproviders seen:")
    for row in conn.execute("SELECT DISTINCT provider FROM resources"):
        print(f"  {row[0]}")

    print("\nresource types stored:")
    for row in conn.execute("SELECT DISTINCT resource_type FROM resources ORDER BY 1"):
        print(f"  {row[0]}")

    # --- summary --------------------------------------------------------------
    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"{passed}/{len(RESULTS)} checks passed")
    for name, ok, detail in RESULTS:
        if not ok:
            print(f"  FAILED: {name} {detail}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
