#!/usr/bin/env python
"""Run the complete reality demo: scan → reconcile → why/impact/graph/simulate.

Uses recorded Anthropic responses from tests/fixtures/ to produce a full
pipeline with mixed conclusions (confirmed/undocumented/possible/declared_only/unknown).

Runs fully offline — zero AWS calls.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
os.chdir(REPO)


def run(label: str, *args: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"{label}")
    print(f"{'=' * 60}")
    cmd = [sys.executable, "-m", "reality"] + list(args)
    result = subprocess.run(cmd, cwd=REPO)
    if result.returncode != 0:
        print(f"(exit code {result.returncode})")


def main() -> int:
    db = "Atest/complex-demo/demo.db"

    # Build the demo database from recorded responses (fully offline)
    print("Building demo database from recorded responses...")
    subprocess.run(
        [sys.executable, "scripts/build_demo_db.py", "--out", db],
        cwd=REPO,
        check=True,
    )

    # 1. Doctor
    run("0. Doctor (environment check)", "--database", db, "doctor")

    # 2. Reconcile - shows mixed conclusions
    run("1. Reconcile (mixed conclusions: confirmed/undocumented/possible/declared_only/unknown)",
        "--database", db, "reconcile")

    # 3. Undocumented only
    run("2. Undocumented findings only",
        "--database", db, "reconcile", "--conclusion", "undocumented")

    # 4. Why a resource
    run("3. Why (documented web instance)",
        "--database", db, "why",
        "terraform/aws/aws_instance/-/-/aws_instance.web")

    # 5. Impact - blast radius
    run("4. Impact (web_sg blast radius)",
        "--database", db, "impact",
        "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg",
        "--fail-on", "high")

    # 6. Graph - incoming (who depends on the SG)
    run("5. Graph (SG blast radius — incoming/dependents)",
        "--database", db, "graph",
        "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg",
        "--output", "mermaid")

    # 7. Graph - outgoing (what the instance depends on)
    run("6. Graph (instance dependencies — outgoing)",
        "--database", db, "graph",
        "terraform/aws/aws_instance/-/-/aws_instance.web",
        "--direction", "outgoing",
        "--output", "mermaid")

    # 8. Simulate
    plan = REPO / "tests" / "fixtures" / "terraform" / "plan_replace.json"
    run("7. Simulate (plan replace targets)",
        "--database", db, "simulate", str(plan))

    # 9. Table output
    run("8. Table output (rich)",
        "--database", db, "reconcile", "--output", "table")

    print(f"\n{'=' * 60}")
    print(f"Demo complete! Database: {db}")
    print(f"Clean up: rm {db}")
    print(f"{'=' * 60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())