"""User settings that persist between runs, and the doctor that inspects them.

Every default in :mod:`reality.config` is local and offline, and AWS is opt-in
per invocation. A settings file must not erode that, so the split is strict:

* The file can supply a **database path**, an **AWS profile**, and an **AWS
  region** - the tedious, repeatable parts of a command line.
* The file can **never** opt in to AWS. ``--aws`` is a flag on a single
  invocation and is deliberately not persisted, because the whole safety
  argument for this tool is that no read reaches AWS unless the person running
  it asked for that read. A file that turned AWS on would mean an audit log
  full of scans nobody initiated.

Resolution order, highest priority first:

1. an explicit command-line flag,
2. the ``REALITY_*`` environment variables,
3. the settings file,
4. the built-in local default.

The file format is TOML (``tomllib`` is standard library on 3.11+). It holds a
flat table of strings, so writing one back is a few lines rather than a
dependency. A malformed file is reported with its path and line rather than
being silently ignored - a typo in a config file should not look like a
missing one.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

#: Overrides the settings-file location, mainly for tests and for CI.
CONFIG_ENV_VAR = "REALITY_CONFIG"

#: The settings file is looked up here first (the XDG convention, which works
#: on every platform), then beside the user's home directory.
CONFIG_RELATIVE_PATHS = (".config/reality/config.toml", ".reality.toml")

#: Environment fallbacks, so a script can set a profile once per session.
ENV_PROFILE = "REALITY_PROFILE"
ENV_REGION = "REALITY_REGION"
ENV_DATABASE = "REALITY_DATABASE"

#: The minimum Python this package supports, checked by ``reality doctor``.
MINIMUM_PYTHON = (3, 12)


class SettingsError(Exception):
    """The settings file exists but could not be used."""


class UserSettings(BaseModel):
    """Persisted preferences. Every field is optional; absent means 'no opinion'."""

    model_config = ConfigDict(frozen=True)

    database: str | None = None
    profile: str | None = None
    region: str | None = None

    @field_validator("database", "profile", "region")
    @classmethod
    def _blank_is_absent(cls, value: str | None) -> str | None:
        """An empty string is a typo, not a request for a default."""
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class ResolvedSetting(BaseModel):
    """One effective value, with the source that supplied it.

    The source travels with the value on purpose: ``reality doctor`` and
    ``reality config`` both need to answer "why is my region eu-west-1?", and a
    bare value cannot answer that.

    ``value`` is optional because "not set anywhere" is a legitimate resolved
    state for the AWS profile and region, which have no defaults by design. It
    is reported as ``not set`` rather than as an error.
    """

    model_config = ConfigDict(frozen=True)

    value: str | None
    source: str


def config_path() -> Path:
    """Where settings are read from and written to.

    ``REALITY_CONFIG`` wins, then ``$XDG_CONFIG_HOME/reality/config.toml``,
    then the XDG path relative to the home directory, then the same shape under
    ``%APPDATA%`` on Windows.
    """
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser() / "reality" / "config.toml"
    home = Path.home()
    for relative in CONFIG_RELATIVE_PATHS:
        candidate = home / relative
        if candidate.parent.is_dir() or relative == CONFIG_RELATIVE_PATHS[0]:
            return candidate
    return home / CONFIG_RELATIVE_PATHS[0]


def load_settings(path: Path | None = None) -> tuple[UserSettings, Path]:
    """Read the settings file, returning it alongside the path used.

    A missing file is not an error: it yields empty settings, because a user
    who has never configured anything is the normal case, not a fault.
    """
    target = path or config_path()
    if not target.is_file():
        return UserSettings(), target
    try:
        raw: dict[str, Any] = tomllib.loads(target.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as err:
        raise SettingsError(f"{target}: {err}") from err
    # A flat table is the whole schema. An unknown key is a typo worth naming
    # rather than a setting to guess at.
    unknown = sorted(set(raw) - {"database", "profile", "region"})
    if unknown:
        raise SettingsError(
            f"{target}: unknown setting(s) {', '.join(unknown)}; "
            f"supported: database, profile, region"
        )
    try:
        return UserSettings.model_validate(raw), target
    except ValueError as err:  # pragma: no cover - the validator accepts any str
        raise SettingsError(f"{target}: {err}") from err


def _toml_escape(value: str) -> str:
    """Quote a value for the hand-written TOML writer.

    Only a double-quoted basic string is emitted, so backslashes and quotes -
    the realistic hazards in a Windows path - have to be escaped.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def save_settings(settings: UserSettings, path: Path | None = None) -> Path:
    """Write settings, replacing the file, and return the path written.

    A single-section file with comments, so it stays readable and hand-editable
    - a config file nobody can read is one nobody will fix. ``None`` fields are
    omitted rather than written empty, so a partial config does not shadow a
    value the user would otherwise get from the environment.
    """
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# reality settings",
        "#",
        "# Written by `reality config init`. Safe to edit by hand.",
        "#",
        "# These are defaults for convenience only. They never opt in to AWS:",
        "# every AWS read still requires --aws on the command line, every run.",
        "",
    ]
    for key, value in (
        ("database", settings.database),
        ("profile", settings.profile),
        ("region", settings.region),
    ):
        if value is not None:
            lines.append(f"{key} = {_toml_escape(value)}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def resolve_setting(
    flag_value: str | None,
    *,
    env_name: str,
    file_value: str | None,
    default: str | None,
) -> ResolvedSetting:
    """Apply the documented precedence for one setting.

    ``flag_value`` is the only non-empty string that can win, which is what
    keeps an explicit command line above a stale file. When nothing supplies a
    value the result is ``(None, "not set")`` rather than an error: an absent
    profile or region is the safe default, and the safety contract depends on
    it being represented as absence rather than as a guess.
    """
    if flag_value and flag_value.strip():
        return ResolvedSetting(value=flag_value.strip(), source="command line")
    env_value = os.environ.get(env_name, "").strip()
    if env_value:
        return ResolvedSetting(value=env_value, source=f"${env_name}")
    # The file value is stripped too, even though `UserSettings` already
    # normalizes it: a blank is a typo, and this function is the single place
    # that decides whether a value counts as supplied.
    file_text = (file_value or "").strip()
    if file_text:
        return ResolvedSetting(value=file_text, source="config file")
    if default:
        return ResolvedSetting(value=default, source="built-in default")
    return ResolvedSetting(value=None, source="not set")


CheckStatus = Literal["ok", "warn", "fail", "skip"]


class Check(BaseModel):
    """One line of a doctor report."""

    model_config = ConfigDict(frozen=True)

    name: str
    status: CheckStatus
    detail: str
    remedy: str | None = None

    @property
    def failed(self) -> bool:
        """Whether this check alone makes the environment unhealthy."""
        return self.status == "fail"


def _python_check() -> Check:
    running = sys.version_info[:2]
    text = ".".join(str(part) for part in sys.version_info[:3])
    if running < MINIMUM_PYTHON:
        needed = f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]}"
        return Check(
            name="python",
            status="fail",
            detail=f"{text} is older than the supported {needed}",
            remedy=f"use Python {needed} or newer",
        )
    return Check(name="python", status="ok", detail=text)


def _package_check() -> Check:
    try:
        from reality import __version__
    except ImportError:  # pragma: no cover - the package is always importable
        return Check(name="reality", status="fail", detail="version unreadable")
    return Check(name="reality", status="ok", detail=__version__)


def _optional_dependency_checks() -> list[Check]:
    """Report the optional extras, since each changes what the tool can do."""
    checks: list[Check] = []
    try:
        import boto3  # noqa: F401
    except ImportError:
        checks.append(
            Check(
                name="boto3",
                status="skip",
                detail="not installed",
                remedy="needed only for AWS reads: pip install 'reality[aws]'",
            )
        )
    else:
        checks.append(Check(name="boto3", status="ok", detail="installed"))

    try:
        import rich  # noqa: F401
    except ImportError:
        checks.append(
            Check(
                name="rich",
                status="skip",
                detail="not installed",
                remedy="needed only for --output table: pip install 'reality[table]'",
            )
        )
    else:
        checks.append(Check(name="rich", status="ok", detail="installed"))
    return checks


def _settings_check(path: Path) -> Check:
    if not path.is_file():
        return Check(
            name="settings",
            status="skip",
            detail=f"no file at {path}",
            remedy="optional: run 'reality config init --set-profile NAME' to create one",
        )
    try:
        load_settings(path)
    except SettingsError as err:
        return Check(
            name="settings",
            status="fail",
            detail=str(err),
            remedy="fix the file, or delete it to fall back to defaults",
        )
    return Check(name="settings", status="ok", detail=str(path))


def _database_check(path: Path) -> Check:
    if not path.exists():
        return Check(
            name="database",
            status="skip",
            detail=f"not created yet ({path})",
            remedy="run: reality scan path/to/state.json",
        )
    if not path.is_file():
        return Check(
            name="database",
            status="fail",
            detail=f"{path} is a directory, not a database file",
            remedy="point --database at a file",
        )
    try:
        from reality.storage.migrations import migrate
        from reality.storage.repositories import ScanStore
        from reality.storage.sqlite import connect
    except ImportError:  # pragma: no cover
        return Check(name="database", status="fail", detail="storage layer unreadable")
    conn = connect(path)
    try:
        migrate(conn)
        store = ScanStore(conn)
        runs = store.scan_runs.count()
        latest = store.scan_runs.latest_discovery_run()
    except Exception as err:  # noqa: BLE001 - doctor reports, it does not raise
        return Check(
            name="database",
            status="fail",
            detail=f"{path}: {err}",
            remedy="the file may not be a reality database; move it aside",
        )
    finally:
        conn.close()
    if runs == 0:
        return Check(
            name="database",
            status="warn",
            detail=f"{path}: no scan runs yet",
            remedy="run: reality scan path/to/state.json",
        )
    return Check(
        name="database",
        status="ok",
        detail=f"{path}: {runs} scan run(s), latest discovery run {latest}",
    )


def _aws_checks(*, opt_in: bool, profile: str | None, region: str | None) -> list[Check]:
    """Check the AWS side, but only as far as the safety contract allows.

    Without an explicit opt-in this reports the opt-in state and stops. It
    never resolves credentials, contacts STS, or touches a profile on its own:
    a diagnostic command that quietly reached the network would undercut the
    guarantee the other commands make.
    """
    if not opt_in:
        return [
            Check(
                name="aws",
                status="skip",
                detail="not opted in; AWS is never contacted without --aws",
                remedy=(
                    "to check the AWS side: reality doctor --aws --profile NAME --region REGION"
                ),
            )
        ]

    checks: list[Check] = []
    try:
        import boto3
    except ImportError:
        return [
            Check(
                name="aws",
                status="fail",
                detail="--aws given but boto3 is not installed",
                remedy="pip install 'reality[aws]'",
            )
        ]

    missing = [name for name, value in (("profile", profile), ("region", region)) if not value]
    if missing:
        checks.append(
            Check(
                name="aws",
                status="fail",
                detail=f"--aws requires {' and '.join(missing)}",
                remedy="rerun with the complete triple: --aws --profile NAME --region REGION",
            )
        )
        return checks

    session_kwargs: dict[str, Any] = {"region_name": region}
    if profile:
        session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
    except Exception as err:  # noqa: BLE001 - doctor reports, it does not raise
        return [
            Check(
                name="aws",
                status="fail",
                detail=f"cannot open profile {profile!r}: {err}",
                remedy="check the profile exists: aws configure list-profiles",
            )
        ]

    try:
        identity = session.client("sts").get_caller_identity()
    except Exception as err:  # noqa: BLE001 - doctor reports, it does not raise
        return [
            Check(
                name="aws",
                status="fail",
                detail=f"credentials for {profile!r} were rejected: {err}",
                remedy=f"refresh them: aws sso login --profile {profile}",
            )
        ]

    account = identity.get("Account", "unknown")
    checks.append(
        Check(
            name="aws",
            status="ok",
            detail=(
                f"profile {profile!r} in {region} resolves to account {account} "
                f"as {identity.get('Arn', 'an unknown principal')}"
            ),
        )
    )
    checks.append(Check(name="aws-region", status="ok", detail=str(region)))
    return checks


def _terraform_check() -> Check:
    """Report whether ``terraform`` is on PATH.

    Informational only. reality never invokes Terraform - it reads documents
    the user exported - so its absence is not a fault, just a note about how
    the user will produce those documents.
    """
    import shutil

    executable = shutil.which("terraform")
    if executable is None:
        return Check(
            name="terraform",
            status="skip",
            detail="not on PATH (not required; reality reads exported JSON)",
            remedy="to export documents yourself: terraform show -json > state.json",
        )
    return Check(name="terraform", status="ok", detail=executable)
