"""Suite-wide isolation from the machine the tests run on.

Both fixtures here are autouse, and both are load-bearing for the safety
contract rather than conveniences.

``isolated_settings`` points the settings file at a per-test temporary path and
clears every ``REALITY_*`` and ``AWS_*`` variable. Without it the suite reads the
developer's own ``~/.config/reality/config.toml``: a saved profile and region
complete the ``--aws`` triple, so ``reality --aws scan`` stops being the partial
selection the test asserts it is, and the suite goes red on a configured machine
while staying green on a clean CI runner. Worse, that same path turns a unit test
into a live AWS scan. Pinning the config here is what makes the offline
guarantee hold because it is true, not because the runner happens to be bare.

``no_real_aws`` replaces each adapter's real client factory with one that fails
the test. Every AWS-facing test injects a scripted fake client, so the real
factory should never be reached; when one is, the cause is a code path that
built a client from the ambient credential chain — the one thing this project
promises never to do by accident. The three ``botocore`` Stubber tests construct
their own session with fake credentials and stub every call, so they never pass
through these factories and keep working.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NoReturn

import pytest

from reality.settings import (
    CONFIG_ENV_VAR,
    ENV_DATABASE,
    ENV_PROFILE,
    ENV_REGION,
)

#: Every variable that could supply a default the tests did not ask for.
_REALITY_VARS = (ENV_DATABASE, ENV_PROFILE, ENV_REGION)

#: Ambient AWS credentials and region hints. Cleared so that a code path which
#: slips past ``no_real_aws`` still has nothing to authenticate with, mirroring
#: the empty values the CI workflow pins.
_AWS_VARS = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)

#: The adapter modules whose ``_default_client_factory`` is the only route this
#: code base has to a real AWS client.
_ADAPTERS_WITH_CLIENTS = ("aws_resources", "cloudtrail", "iam")


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin the settings file and clear inherited environment defaults.

    The path deliberately does not exist: "the user has never configured
    anything" is the state every test should start from. A test that wants a
    settings file writes one and re-points ``REALITY_CONFIG`` itself, which
    overrides this fixture cleanly because the test body runs after it.
    """
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "reality-config" / "config.toml"))
    for variable in (*_REALITY_VARS, *_AWS_VARS):
        monkeypatch.delenv(variable, raising=False)
    yield


@pytest.fixture(autouse=True)
def no_real_aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make any attempt to build a real AWS client fail the test loudly."""

    def refuse(profile: str, region: str) -> NoReturn:
        raise AssertionError(
            "a test tried to build a real AWS client "
            f"(profile={profile!r}, region={region!r}). Tests must inject a "
            "scripted client factory; reaching the default factory means the "
            "code path would have used real credentials."
        )

    for name in _ADAPTERS_WITH_CLIENTS:
        module: Any = importlib.import_module(f"reality.adapters.{name}")
        monkeypatch.setattr(module, "_default_client_factory", refuse)
    yield
