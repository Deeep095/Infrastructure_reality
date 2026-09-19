"""Integration test for the documented demo: scan to simulate, fully offline.

Mirrors the README walkthrough against the shipped fixtures. Every AWS
credential variable is deleted and new sockets are refused for the duration,
proving the local slice needs no credentials and no network. Terraform is
never invoked — the fixtures are pre-exported JSON documents, which is the
only form the tool accepts.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from reality import cli

TESTS = Path(__file__).resolve().parents[1]
TF_STATE = TESTS / "fixtures" / "terraform" / "state.json"
TF_PLAN = TESTS / "fixtures" / "terraform" / "plan_replace.json"

TF_WEB_SG = "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"
TF_WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"
TF_PRIMARY = "terraform/aws/aws_db_instance/-/-/aws_db_instance.primary"

#: Every credential-carrying environment variable the AWS SDK family reads.
AWS_ENV_VARS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
)


class NoNetwork:
    """``socket.socket`` stand-in: any connection attempt fails the test."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("the local demo must not open a network connection")


@pytest.fixture()
def offline(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """No credentials in the environment, no sockets available."""
    for name in AWS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(socket, "socket", NoNetwork)
    yield


def test_readme_demo_runs_offline(
    offline: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "demo.db"
    base = ["--database", str(database)]

    # 1. Scan the declared world from a local state export.
    assert cli.main([*base, "scan", str(TF_STATE)]) == cli.EXIT_OK
    scan_out = capsys.readouterr().out
    assert "terraform: available" in scan_out
    assert "aws_resources: not_requested" in scan_out
    assert database.exists()

    # 2. Why: relationships, evidence, findings, and coverage limitations.
    assert cli.main([*base, "why", TF_WEB_SG]) == cli.EXIT_OK
    why_out = capsys.readouterr().out
    assert why_out.startswith(f"reality: why {TF_WEB_SG}\n")
    assert f"<- {TF_WEB} attached_to [terraform_declared]" in why_out
    assert "coverage limitations" in why_out

    # 3. Impact: reverse traversal; unreconciled dependents stay unknown.
    assert cli.main([*base, "impact", TF_WEB_SG]) == cli.EXIT_OK
    impact_out = capsys.readouterr().out
    assert "risk: medium" in impact_out
    assert f"- {TF_PRIMARY} (depth 1, unknown)" in impact_out
    assert f"- {TF_WEB} (depth 1, unknown)" in impact_out
    assert "run reality reconcile" in impact_out

    # 4. Simulate: the plan's replace target, resolved and reported — not applied.
    assert cli.main([*base, "simulate", str(TF_PLAN)]) == cli.EXIT_OK
    simulate_out = capsys.readouterr().out
    assert "read-only; the plan is never applied" in simulate_out
    assert "overall risk: low" in simulate_out
    assert f"aws_instance.web [replace] -> {TF_WEB}" in simulate_out
