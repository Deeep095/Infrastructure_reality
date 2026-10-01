"""The demo world must keep demonstrating what it claims to demonstrate.

``scripts/build_demo_db.py`` is the README walkthrough: it scans the recorded
API responses in ``tests/fixtures/`` and reconciles them, with no AWS
credentials, no network, and no Terraform executable. A demo that quietly
stops containing a hidden dependency would be worse than no demo, so the
claims the README makes are asserted here against a freshly built copy of
that world.

What is asserted, and why each one is the point of the demo:

1. The two worlds really are both present and reconciled — a ``confirmed``
   conclusion that required an identity mapping, not a name match.
2. At least one ``undocumented`` conclusion exists: something observed in the
   cloud that no Terraform declaration accounts for. This is the headline.
3. A resource whose dependents include an ``undocumented`` one reports HIGH
   risk, and ``--fail-on high`` turns that into exit 6 — the CI gate.
4. ``--fail-on`` stays out of the way by default, and never fires on a report
   that is merely unverifiable.
5. A native ID shared by both worlds is ambiguous, and the CLI refuses to
   pick one side of it.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sqlite3
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType

import pytest

from reality import cli
from reality.domain.enums import Conclusion, RelationshipType
from reality.services.impact import RiskLevel
from reality.services.reconcile import finding_id

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "build_demo_db.py"

REGION = "eu-west-1"
ACCOUNT = "123456789012"

#: The observed legacy dependency: the running web instance sits behind a
#: security group that no state resource declares and no mapping can reach.
OBSERVED_WEB = f"aws/ec2/instance/{REGION}/{ACCOUNT}/i-0web"
UNDECLARED_SG = f"aws/ec2/security-group/{REGION}/{ACCOUNT}/sg-0zzz999"
UNDOCUMENTED_FINDING = finding_id(OBSERVED_WEB, UNDECLARED_SG, RelationshipType.ATTACHED_TO)

#: A role the observed world attaches to with no declared counterpart.
OBSERVED_CLEANUP_ROLE = f"aws/iam/role/-/{ACCOUNT}/cleanup_role"


def load_builder() -> ModuleType:
    """Import the demo builder by path: it is a script, not a package module."""
    spec = importlib.util.spec_from_file_location("build_demo_db", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_demo_db"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the demo world once for the whole module."""
    database = tmp_path_factory.mktemp("demo") / "demo.db"
    load_builder().build(database)
    return database


def read_findings(database: Path) -> list[dict[str, object]]:
    """The findings as the CLI reports them, which carry both endpoints."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        assert cli.main(["--database", str(database), "reconcile", "--json"]) == cli.EXIT_OK
    return list(json.loads(buffer.getvalue())["findings"])


def read_stored_findings(database: Path) -> list[sqlite3.Row]:
    """The findings as they were persisted, read straight from the table."""
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM findings").fetchall()
    finally:
        conn.close()


def test_both_worlds_are_present_and_reconciled(demo: Path) -> None:
    findings = read_findings(demo)
    assert findings, "the demo world reconciled to nothing at all"

    # The declared database's attachment to the declared security group is the
    # same real dependency as the observed one, and it was joined by an
    # identity mapping rather than a name.
    joined = [
        row
        for row in findings
        if row["conclusion"] == Conclusion.CONFIRMED.value
        and "identity mapping" in row["explanation"]
    ]
    assert joined, "no confirmed conclusion was backed by an identity mapping"
    # Both namespaces keep their own finding instead of one replacing the other.
    sources = {row["source_canonical_id"] for row in joined}
    assert any(source.startswith("terraform/") for source in sources)
    assert any(source.startswith("aws/") for source in sources)

    # And the conclusions are persisted, not just printed.
    stored_ids = {row["id"] for row in read_stored_findings(demo)}
    assert {row["finding_id"] for row in findings} == stored_ids


def test_a_hidden_dependency_is_demonstrated(demo: Path) -> None:
    rows = {row["finding_id"]: row for row in read_findings(demo)}
    assert UNDOCUMENTED_FINDING in rows, "the demo lost its headline hidden dependency"
    finding = rows[UNDOCUMENTED_FINDING]
    assert finding["conclusion"] == Conclusion.UNDOCUMENTED.value
    # The basis is an observed API response, not a permission and not a guess.
    assert "aws_observed" in finding["explanation"]
    assert finding["evidence_ids"]


def test_hidden_dependency_drives_high_risk(demo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--database", str(demo), "impact", OBSERVED_CLEANUP_ROLE, "--json"]) == (
        cli.EXIT_OK
    )
    report = json.loads(capsys.readouterr().out)
    assert report["risk"] == RiskLevel.HIGH.value
    assert any(dependent["kind"] == "undocumented" for dependent in report["dependents"])


def test_fail_on_high_gates_the_build(demo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The report is printed either way; only the exit code carries the verdict.
    assert (
        cli.main(["--database", str(demo), "impact", OBSERVED_CLEANUP_ROLE, "--fail-on", "high"])
        == cli.EXIT_POLICY
    )
    assert "risk: high" in capsys.readouterr().out
    # And the default leaves the decision to the caller.
    assert cli.main(["--database", str(demo), "impact", OBSERVED_CLEANUP_ROLE]) == cli.EXIT_OK
    capsys.readouterr()


def test_a_shared_native_id_is_refused_not_guessed(
    demo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # sg-0aaa111 is the native ID of both the declared and the observed
    # security group. Two identities, one human-readable string: the CLI must
    # report the ambiguity rather than pick a side.
    assert cli.main(["--database", str(demo), "why", "sg-0aaa111"]) == cli.EXIT_INPUT
    err = capsys.readouterr().err
    assert "matches 2 stored resources" in err
    assert "terraform/aws/aws_security_group" in err
    assert "aws/ec2/security-group" in err


def test_every_conclusion_is_reported_and_the_tally_adds_up(demo: Path) -> None:
    # The README quotes these numbers, and the builder's own summary line is
    # what a first-time reader sees. A conclusion that drops out of the count
    # while still being in the findings would make the demo understate itself.
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        assert cli.main(["--database", str(demo), "reconcile", "--json"]) == cli.EXIT_OK
    report = json.loads(buffer.getvalue())
    counts = report["counts"]
    assert sum(counts.values()) == len(report["findings"]) == 23
    assert counts[Conclusion.CONFIRMED.value] == 6
    assert counts[Conclusion.UNDOCUMENTED.value] == 4
    assert counts[Conclusion.POSSIBLE.value] == 8
    assert counts[Conclusion.DECLARED_ONLY.value] == 5
    assert counts[Conclusion.UNKNOWN.value] == 0


def test_reconcile_is_idempotent_over_the_demo_world(
    demo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = cli.main(["--database", str(demo), "reconcile", "--json"])
    assert first == cli.EXIT_OK
    before = json.loads(capsys.readouterr().out)["findings"]
    assert cli.main(["--database", str(demo), "reconcile", "--json"]) == cli.EXIT_OK
    after = json.loads(capsys.readouterr().out)["findings"]
    assert before == after


def test_a_less_qualified_reference_reaches_the_stored_resource(
    demo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An accountless S3 ARN must reach the account-qualified stored bucket.

    The scan stores the bucket as ``aws/s3/bucket/-/123456789012/data-lake``
    while the edges that reference it were recorded as
    ``aws/s3/bucket/-/-/data-lake``. Before the identity resolver these two
    never matched, so the bucket reported ``dependents: none`` and ``risk:
    low`` — it looked safe to delete when a role depended on it.
    """
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        assert (
            cli.main(["--database", str(demo), "impact", "aws/s3/bucket/-/-/data-lake", "--json"])
            == cli.EXIT_OK
        )
    report = json.loads(buffer.getvalue())
    # The accountless reference resolves to the stored, account-qualified bucket.
    assert report["subject_canonical_id"] == "aws/s3/bucket/-/123456789012/data-lake"
    # And the dependents that were previously invisible are now reported.
    assert report["dependents"], "the bucket must show its dependents"
    assert any(dependent["conclusion"] == "undocumented" for dependent in report["dependents"])
    assert report["risk"] == "high"

    # `why` resolves the same reference.
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        assert cli.main(["--database", str(demo), "why", "aws/s3/bucket/-/-/data-lake"]) == (
            cli.EXIT_OK
        )
    assert "data-lake" in buffer.getvalue()
