#!/usr/bin/env python
"""Run the complete reality demo with real AWS data (offline replay).

Uses the pre-recorded reality.db from a real AWS scan to show the full pipeline
in action. All data is from recorded responses, no live AWS calls.
"""

import sys
import os

# Ensure we're using the src directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
os.chdir(os.path.dirname(__file__))

from reality import cli

DB = "reality.db"  # Pre-recorded AWS scan

print("=" * 60)
print("Reality Complex Demo")
print("Using pre-recorded AWS scan from reality.db")
print("=" * 60)

# 1. Show environment
print("\n## 0. Doctor (environment check)")
cli.main(["--database", DB, "doctor"])

# 2. Reconcile - what did we find?
print("\n## 1. Reconcile (findings by conclusion)")
cli.main(["--database", DB, "reconcile"])

# 3. Undocumented resources
print("\n## 2. Undocumented findings only")
cli.main(["--database", DB, "reconcile", "--conclusion", "undocumented"])

# 4. Why a specific resource
print("\n## 3. Why (Resource Explorer service role)")
# Use the canonical ID that resolves correctly
canonical = "aws/iam/role/-/905418449359/AmazonSSMAutomationRole"
cli.main(["--database", DB, "why", canonical])

# 5. Impact - blast radius
print("\n## 4. Impact (SSM Automation Role blast radius)")
cli.main(["--database", DB, "impact", canonical, "--fail-on", "high"])

# 6. Graph - mermaid with blast radius
print("\n## 5. Graph (blast radius of SSM Automation Role)")
cli.main(["--database", DB, "graph", canonical, "--output", "mermaid"])

# 7. Graph - dependencies direction
print("\n## 6. Graph (dependencies, with unresolved)")
cli.main(["--database", DB, "graph", canonical, "--direction", "outgoing", "--include-unresolved", "--output", "mermaid"])

# 8. Full impact with table output
print("\n## 7. Impact table format")
cli.main(["--database", DB, "impact", canonical, "--output", "table"])

print("\n" + "=" * 60)
print("Demo complete!")
print(f"Database: {DB} (pre-recorded, safe to delete)")
print("=" * 60)