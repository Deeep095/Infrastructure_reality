"""Scan a running AWS emulator end to end (opt-in).

Every other AWS-facing test injects fake clients. This one sends real boto3
requests over HTTP to an AWS-compatible emulator, seeded by
``scripts/seed_emulator.py``, and checks that ``scan --endpoint-url`` followed
by ``reconcile`` reaches the conclusions that world was built to produce.

It is skipped unless ``REALITY_EMULATOR_ENDPOINT`` names an emulator on
loopback, so the default suite stays offline::

    moto_server -p 5000
    REALITY_EMULATOR_ENDPOINT=http://127.0.0.1:5000 python -m pytest \
    tests/integration/test_emulator.py

Credentials come from a throwaway profile the seeder writes under ``tmp_path``;
``AWS_CONFIG_FILE`` and ``AWS_SHARED_CREDENTIALS_FILE`` point there for the
duration of the test, so the developer's own ``~/.aws`` is never read.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

from reality import cli
from reality.domain.enums import Conclusion

ENDPOINT = os.environ.get("REALITY_EMULATOR_ENDPOINT", "")
REGION = "eu-west-1"
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "seed_emulator.py"

pytestmark = [
    pytest.mark.skipif(
        not ENDPOINT, reason="set REALITY_EMULATOR_ENDPOINT to a running emulator to enable"
    ),
    # Lets the real client factories run, and only against a loopback endpoint.
    pytest.mark.emulator,
]


def load_seeder() -> ModuleType:
    """Import the seeder by path: it is a script, not a package module."""
    spec = importlib.util.spec_from_file_location("seed_emulator", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_emulator"] = module
    spec.loader.exec_module(module)
    return module


def test_scan_and_reconcile_against_the_emulator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("boto3")
    seeder = load_seeder()
    world = seeder.seed(ENDPOINT, REGION, tmp_path / "world")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(world.config_file))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(world.credentials_file))
    for name in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    database = tmp_path / "emulator.db"
    scan = [
        "--database",
        str(database),
        "scan",
        str(world.state_path),
        "--aws",
        "--profile",
        seeder.PROFILE,
        "--region",
        REGION,
        "--endpoint-url",
        ENDPOINT,
    ]
    assert cli.main(scan) == cli.EXIT_OK
    capsys.readouterr()

    assert cli.main(["--database", str(database), "reconcile", "--json"]) == cli.EXIT_OK
    findings = json.loads(capsys.readouterr().out)["findings"]
    by_pair = {
        (row["source_canonical_id"], row["target_canonical_id"]): row["conclusion"]
        for row in findings
    }

    account, ids = world.account, world.ids
    instance = f"aws/ec2/instance/{REGION}/{account}/{ids['instance']}"
    web_sg = f"aws/ec2/security-group/{REGION}/{account}/{ids['web_sg']}"
    legacy_sg = f"aws/ec2/security-group/{REGION}/{account}/{ids['legacy_sg']}"
    cleanup = f"aws/lambda/function/{REGION}/{account}/cleanup"
    cleanup_role = f"aws/iam/role/-/{account}/cleanup_role"

    # Declared and observed, joined through the state's ARN.
    assert by_pair[(instance, web_sg)] == Conclusion.CONFIRMED.value
    # Observed with no declaration: the drift the tool exists to find.
    assert by_pair[(instance, legacy_sg)] == Conclusion.UNDOCUMENTED.value
    assert by_pair[(cleanup, cleanup_role)] == Conclusion.UNDOCUMENTED.value

    conclusions = [row["conclusion"] for row in findings]
    assert conclusions.count(Conclusion.CONFIRMED.value) == 6  # 3 dependencies, one per side
    assert Conclusion.DECLARED_ONLY.value in conclusions
    # Both sides were consulted, so nothing is left undecided.
    assert Conclusion.UNKNOWN.value not in conclusions

    # The roles' S3 grants are possible, not unknown, even though no CloudTrail
    # was requested: LookupEvents never shows data-plane usage, so its absence
    # cannot block this conclusion either way.
    roles = {f"aws/iam/role/-/{account}/{name}" for name in ("processor_role", "cleanup_role")}
    possible = [row for row in findings if row["conclusion"] == Conclusion.POSSIBLE.value]
    assert possible, "the roles' S3 grants should surface as possible permissions"
    for row in possible:
        assert row["relationship_type"] == "permission_on"
        assert row["source_canonical_id"] in roles
        assert row["unavailable_sources"] == []
