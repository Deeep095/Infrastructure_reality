"""Settings resolution, `reality config`, and `reality doctor`.

The safety-relevant property is the one that is easiest to break by accident:
a settings file can supply a profile and a region, but it can never opt in to
AWS. If that ever regressed, a user with a config file would start making AWS
calls they did not ask for, with nothing in their command line to show why.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from reality import cli
from reality.config import RealityConfig
from reality.services.scan import ScanReport
from reality.settings import (
    CONFIG_ENV_VAR,
    ENV_DATABASE,
    ENV_PROFILE,
    ENV_REGION,
    SettingsError,
    UserSettings,
    config_path,
    load_settings,
    resolve_setting,
    save_settings,
)

STATE = Path(__file__).resolve().parents[1] / "fixtures" / "terraform" / "state.json"


@pytest.fixture()
def settings_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated settings file, so no test touches the real one."""
    path = tmp_path / "config.toml"
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    return path


# --- resolution precedence ------------------------------------------------------


def test_command_line_beats_everything(settings_file: Path) -> None:
    save_settings(UserSettings(profile="from-file", region="eu-west-1"), settings_file)
    resolved = resolve_setting(
        "from-flag",
        env_name=ENV_PROFILE,
        file_value="from-file",
        default=None,
    )
    assert (resolved.value, resolved.source) == ("from-flag", "command line")


def test_environment_beats_the_file(settings_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_settings(UserSettings(profile="from-file"), settings_file)
    monkeypatch.setenv(ENV_PROFILE, "from-env")
    resolved = resolve_setting(None, env_name=ENV_PROFILE, file_value="from-file", default=None)
    assert (resolved.value, resolved.source) == ("from-env", "$REALITY_PROFILE")


def test_file_beats_the_built_in_default(settings_file: Path) -> None:
    save_settings(UserSettings(database="from-file.db"), settings_file)
    resolved = resolve_setting(
        None, env_name=ENV_DATABASE, file_value="from-file.db", default="reality.db"
    )
    assert (resolved.value, resolved.source) == ("from-file.db", "config file")


def test_absent_value_resolves_to_none_not_an_error() -> None:
    """No profile anywhere is the safe default, not a failure."""
    resolved = resolve_setting(None, env_name=ENV_REGION, file_value=None, default=None)
    assert resolved.value is None
    assert resolved.source == "not set"


def test_empty_values_do_not_count(monkeypatch: pytest.MonkeyPatch, settings_file: Path) -> None:
    """A blank string is a typo, not a value."""
    monkeypatch.setenv(ENV_REGION, "   ")
    resolved = resolve_setting("", env_name=ENV_REGION, file_value="  ", default=None)
    assert resolved.value is None


# --- the file format ------------------------------------------------------------


def test_round_trip(settings_file: Path) -> None:
    written = save_settings(
        UserSettings(database="a.db", profile="sandbox", region="eu-west-1"), settings_file
    )
    loaded, path = load_settings(written)
    assert (loaded.database, loaded.profile, loaded.region) == (
        "a.db",
        "sandbox",
        "eu-west-1",
    )
    assert path == written


def test_written_file_is_readable_toml_with_its_comments(settings_file: Path) -> None:
    """A config file nobody can read is one nobody will fix."""
    save_settings(UserSettings(profile="sandbox"), settings_file)
    text = settings_file.read_text(encoding="utf-8")
    assert text.startswith("# reality settings")
    assert 'profile = "sandbox"' in text


def test_windows_path_survives_the_round_trip(settings_file: Path) -> None:
    """Backslashes are the realistic hazard in a hand-written TOML file."""
    windows = r"C:\Users\deepa\reality.db"
    save_settings(UserSettings(database=windows), settings_file)
    loaded, _ = load_settings(settings_file)
    assert loaded.database == windows


def test_missing_file_is_not_an_error(tmp_path: Path) -> None:
    settings, path = load_settings(tmp_path / "absent.toml")
    assert settings == UserSettings()
    assert path == tmp_path / "absent.toml"


def test_unset_fields_are_omitted_not_written_empty(settings_file: Path) -> None:
    """A partial config must not shadow the environment with empties."""
    save_settings(UserSettings(profile="sandbox"), settings_file)
    assert "region" not in settings_file.read_text(encoding="utf-8")


def test_malformed_file_names_the_path_and_problem(tmp_path: Path) -> None:
    bad = tmp_path / "config.toml"
    bad.write_text("this is not = = toml", encoding="utf-8")
    with pytest.raises(SettingsError) as caught:
        load_settings(bad)
    # The path is in the message, so the user knows which file to fix, and the
    # message is a str() not a regex match: Windows paths are full of
    # backslashes that would blow up a pattern-based assertion.
    assert str(bad) in str(caught.value)


def test_unknown_key_is_reported_rather_than_guessed(tmp_path: Path) -> None:
    """A typo should say what is supported, not silently do nothing."""
    bad = tmp_path / "config.toml"
    bad.write_text('profiel = "sandbox"\n', encoding="utf-8")
    with pytest.raises(SettingsError, match="profiel"):
        load_settings(bad)


def test_config_path_honours_the_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CONFIG_ENV_VAR, "/tmp/explicit.toml")
    assert config_path() == Path("/tmp/explicit.toml")


# --- reality config --------------------------------------------------------------


def test_config_show_reports_each_source(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    save_settings(UserSettings(profile="sandbox", region="eu-west-1"), settings_file)
    assert cli.main(["config"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "config file" in out
    assert "sandbox" in out
    assert "eu-west-1" in out


def test_config_show_accepts_a_flag_to_inspect(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`config --region X` answers "what would X win with?"."""
    save_settings(UserSettings(region="eu-west-1"), settings_file)
    assert cli.main(["config", "--region", "ap-south-1"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "ap-south-1" in out
    assert "command line" in out


def test_config_show_states_that_opt_in_is_never_persisted(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    save_settings(UserSettings(profile="sandbox"), settings_file)
    cli.main(["config"])
    assert "never persisted" in capsys.readouterr().out


def test_config_init_writes_and_then_reads(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(
        [
            "config",
            "init",
            "--set-profile",
            "sandbox",
            "--set-region",
            "eu-west-1",
        ]
    )
    assert code == cli.EXIT_OK
    assert "wrote" in capsys.readouterr().out
    loaded, _ = load_settings(settings_file)
    assert (loaded.profile, loaded.region) == ("sandbox", "eu-west-1")


def test_config_init_merges_rather_than_replaces(settings_file: Path) -> None:
    """Re-running init must not silently drop an earlier setting."""
    cli.main(["config", "init", "--set-profile", "sandbox"])
    cli.main(["config", "init", "--set-region", "eu-west-1"])
    loaded, _ = load_settings(settings_file)
    assert loaded.profile == "sandbox"
    assert loaded.region == "eu-west-1"


def test_config_init_with_nothing_to_write_is_usage(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["config", "init"]) == cli.EXIT_USAGE
    assert "nothing to write" in capsys.readouterr().out
    assert not settings_file.exists()


def test_config_path_prints_the_path(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["config", "path"]) == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == str(settings_file)


def test_malformed_settings_file_is_reported_not_ignored(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings_file.write_text("= = broken", encoding="utf-8")
    assert cli.main(["config"]) == cli.EXIT_CONFIG
    assert "reality: error:" in capsys.readouterr().err


# --- the opt-in guarantee --------------------------------------------------------


def test_a_configured_profile_does_not_enable_aws(settings_file: Path, tmp_path: Path) -> None:
    """The safety property: a saved profile never becomes an AWS opt-in.

    ``--aws`` is deliberately not a settings field, so it cannot be persisted.
    A local-only command with a fully configured profile must still be local.
    """
    save_settings(UserSettings(profile="sandbox", region="eu-west-1"), settings_file)
    database = tmp_path / "scan.db"
    assert cli.main(["--database", str(database), "scan", str(STATE)]) == cli.EXIT_OK
    # The scan reports every AWS side as unrequested, which is only possible
    # if the saved profile did not reach an adapter.
    import sqlite3

    conn = sqlite3.connect(database)
    sources = {row[0] for row in conn.execute("SELECT source FROM scan_runs")}
    assert sources == {"terraform_state"}
    conn.close()


def test_configured_profile_lets_aws_work_from_one_flag(
    settings_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The payoff of P1-8: a configured profile means `--aws` alone suffices.

    This is the whole point of persisting a profile and region - the tedious
    half of the triple is remembered, while the opt-in half is still typed.

    The scan service is stubbed out, so this asserts what it means to assert -
    that the saved profile and region reached a validated config - without
    making a single AWS call. Letting the real service run instead would make
    the result depend on whether the developer happens to have credentials for
    the configured profile, and on a machine that does it is a live scan.
    """
    save_settings(UserSettings(profile="sandbox", region="eu-west-1"), settings_file)
    seen: dict[str, object] = {}

    class StubService:
        @classmethod
        def from_config(cls, config, store, **kwargs):  # type: ignore[no-untyped-def]
            seen["config"] = config
            return cls()

        def run(self, paths):  # type: ignore[no-untyped-def]
            return ScanReport(scan_run_id=1)

    monkeypatch.setattr(cli, "ScanService", StubService)
    code = cli.main(["--aws", "scan", str(STATE), "--database", str(tmp_path / "scan.db")])

    err = capsys.readouterr().err
    assert code == cli.EXIT_OK
    assert "requires an explicit" not in err
    # Past config validation and into the AWS path, carrying the saved values.
    config = seen["config"]
    assert isinstance(config, RealityConfig)
    assert (config.aws_opt_in, config.aws_profile, config.aws_region) == (
        True,
        "sandbox",
        "eu-west-1",
    )


def test_missing_boto3_is_an_install_hint_not_a_traceback(
    settings_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--aws` without the extra should say how to fix it, not crash.

    boto3 is imported lazily inside the adapters, so without the guard in
    ``require_aws`` a missing extra surfaces as an ImportError traceback from
    three frames down. This only runs where boto3 is absent, which is exactly
    the offline/CI-without-extras configuration the guard is for.
    """
    if importlib.util.find_spec("boto3") is not None:
        pytest.skip("boto3 is installed; the missing-extra path is unreachable")
    save_settings(UserSettings(profile="sandbox", region="eu-west-1"), settings_file)
    code = cli.main(["--aws", "scan", str(STATE), "--database", str(tmp_path / "scan.db")])
    err = capsys.readouterr().err
    assert code == cli.EXIT_CONFIG
    assert "pip install" in err
    assert "Traceback" not in err


def test_aws_without_a_profile_anywhere_is_refused(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With nothing configured, `--aws` alone is an incomplete selection."""
    assert cli.main(["--aws", "scan", str(STATE), "--database", "unused.db"]) == cli.EXIT_CONFIG
    assert "--aws" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["why", "impact", "simulate", "reconcile"])
def test_an_incomplete_opt_in_is_refused_by_every_command(
    command: str, settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--aws` means the same thing whichever subcommand carries it.

    Only `scan` used to enforce the complete triple, so `reality --aws why X`
    silently ignored the opt-in while `scan` refused it. A flag that is
    enforced in one place and ignored in another is worse than no flag: the
    user cannot tell which reading of their command actually happened.
    """
    argv = [command] if command in {"reconcile"} else [command, "some-id"]
    assert cli.main(["--aws", *argv, "--database", "unused.db"]) == cli.EXIT_CONFIG
    assert "requires an explicit" in capsys.readouterr().err


def test_the_full_triple_passes_validation_on_every_command(
    settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The complement: a complete triple is never refused by config checks."""
    save_settings(UserSettings(profile="deepanshu", region="us-east-1"), settings_file)
    cli.main(["--aws", "why", "some-id", "--database", "unused.db"])
    err = capsys.readouterr().err
    assert "requires an explicit" not in err


# --- reality doctor ---------------------------------------------------------------


def test_doctor_reports_a_healthy_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "absent.toml"))
    code = cli.main(["--database", str(tmp_path / "absent.db"), "doctor"])
    out = capsys.readouterr().out
    # A missing database and settings file are skips, not failures: both leave
    # the tool usable, and the first run of any tool has neither.
    assert code == cli.EXIT_OK
    assert "environment looks usable" in out
    assert "python" in out
    assert "not created yet" in out


def test_doctor_does_not_contact_aws_without_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A diagnostic must not quietly reach the network."""
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "absent.toml"))
    cli.main(["--database", str(tmp_path / "absent.db"), "doctor"])
    out = capsys.readouterr().out
    assert "not opted in" in out
    assert "never contacted without --aws" in out


def test_doctor_flags_a_broken_settings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.toml"
    path.write_text("= = broken", encoding="utf-8")
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    code = cli.main(["--database", str(tmp_path / "absent.db"), "doctor"])
    assert code == cli.EXIT_UNHEALTHY
    assert "settings" in capsys.readouterr().out


def test_doctor_fails_on_a_directory_as_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "absent.toml"))
    as_dir = tmp_path / "not-a-file.db"
    as_dir.mkdir()
    code = cli.main(["--database", str(as_dir), "doctor"])
    assert code == cli.EXIT_UNHEALTHY
    assert "directory" in capsys.readouterr().out


def test_doctor_exits_zero_with_a_populated_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "absent.toml"))
    database = tmp_path / "scan.db"
    assert cli.main(["--database", str(database), "scan", str(STATE)]) == cli.EXIT_OK
    capsys.readouterr()
    code = cli.main(["--database", str(database), "doctor"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "scan run(s)" in out


def test_doctor_output_is_not_json_safe_but_stays_on_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Doctor's plain text is a human surface; it must not crash on encoding."""
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "absent.toml"))
    cli.main(["--database", str(tmp_path / "absent.db"), "doctor"])


# --- global flags still resolve ---------------------------------------------------


def test_database_flag_is_honoured_after_the_change(
    tmp_path: Path, settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A regression guard: --database must not be swallowed by resolution.

    The settings layer reads the flag through a shared accessor; if that
    accessor ever returns ``None`` for the Path-typed flag, every command would
    silently write to the default database instead of the requested one.
    """
    save_settings(UserSettings(database=str(tmp_path / "from-file.db")), settings_file)
    requested = tmp_path / "from-flag.db"
    assert cli.main(["--database", str(requested), "scan", str(STATE)]) == cli.EXIT_OK
    assert requested.exists()
    assert not (tmp_path / "from-file.db").exists()
    assert str(requested) in capsys.readouterr().out


def test_database_flag_before_or_after_subcommand(tmp_path: Path, settings_file: Path) -> None:
    before = tmp_path / "before.db"
    after = tmp_path / "after.db"
    assert cli.main(["--database", str(before), "scan", str(STATE)]) == cli.EXIT_OK
    assert cli.main(["scan", str(STATE), "--database", str(after)]) == cli.EXIT_OK
    assert before.exists()
    assert after.exists()


def test_environment_database_is_used_when_no_flag(
    tmp_path: Path, settings_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from_env = tmp_path / "from-env.db"
    monkeypatch.setenv(ENV_DATABASE, str(from_env))
    assert cli.main(["scan", str(STATE)]) == cli.EXIT_OK
    assert from_env.exists()


def test_json_output_still_parses(
    tmp_path: Path, settings_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The settings layer must not disturb machine-readable output."""
    database = tmp_path / "scan.db"
    cli.main(["--database", str(database), "scan", str(STATE)])
    capsys.readouterr()
    assert (
        cli.main(["--database", str(database), "why", "aws_security_group.web_sg", "--json"])
        == cli.EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["resource"]["canonical_id"].endswith("aws_security_group.web_sg")
