#!/usr/bin/env python
"""Run the complete reality demo: scan → reconcile → why/impact/graph/simulate"""

import sys
import os

# Ensure we're using the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
os.chdir(os.path.dirname(__file__))

from reality import cli

DB = "demo.db"
STATE = "terraform/state.json"
PLAN = "terraform/plan.json"

print("=" * 60)
print("Reality Demo")
print("=" * 60)

# Clean previous run
if os.path.exists(DB):
    os.remove(DB)

# 1. Scan
print("\n## 1. Scan (local Terraform state only)")
cli.main(["--database", DB, "scan", STATE])

# 2. Reconcile
print("\n## 2. Reconcile")
cli.main(["--database", DB, "reconcile"])

# 3. Why
print("\n## 3. Why (web instance)")
cli.main(["--database", DB, "why", "terraform/aws/aws_instance/-/-/aws_instance.web"])

# 4. Impact
print("\n## 4. Impact (security group blast radius)")
cli.main(["--database", DB, "impact", "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg", "--fail-on", "high"])
print(f"Exit code: {cli.EXIT_USAGE}")

# 5. Graph (incoming = dependents/blast radius)
print("\n## 5. Graph (who depends on the security group)")
cli.main(["--database", DB, "graph", "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg", "--output", "mermaid"])

# 6. Graph (outgoing = dependencies)
print("\n## 6. Graph (what the web instance depends on)")
cli.main(["--database", DB, "graph", "terraform/aws/aws_instance/-/-/aws_instance.web", "--direction", "outgoing", "--output", "mermaid"])

# 7. Simulate (if plan exists)
if os.path.exists(PLAN):
    print("\n## 7. Simulate (plan replace targets)")
    cli.main(["--database", DB, "simulate", PLAN])
else:
    print("\n## 7. Simulate - no plan.json, skipping")

print("\nDemo complete!")
print(f"Database: {DB}")
print(f"Clean up: rm {DB}")