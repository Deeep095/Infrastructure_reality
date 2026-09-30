"""The optional display dependency must stay optional.

``rich`` powers ``--output table`` and nothing else. It is imported lazily,
inside the four table renderers, so that a plain install without it can still
import every module and run every other command. These tests pin that: they
simulate a missing ``rich`` and assert the CLI degrades to a clear usage error
instead of a ``ModuleNotFoundError`` traceback at import time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from reality import cli

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"


class TestOptionalRichDependency:
    """The table renderer must not become a hard requirement for the CLI.

    rich is an optional display dependency imported lazily inside the table
    renderers. This module (and every other command) used to import it at
    module scope, which meant that a plain `pip install -e .` without rich
    broke *every* subcommand at import time with a bare ModuleNotFoundError.
    These tests pin the lazy behaviour so that cannot regress.
    """

    @staticmethod
    def _block_rich(monkeypatch: pytest.MonkeyPatch) -> None:
        """Make `import rich` fail, whatever is already in sys.modules."""
        import builtins

        real_import = builtins.__import__

        def guarded(name: str, *args: object, **kwargs: object) -> object:
            if name == "rich" or name.startswith("rich."):
                raise ImportError("No module named 'rich'")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        for module in [name for name in sys.modules if name == "rich" or name.startswith("rich.")]:
            monkeypatch.delitem(sys.modules, module, raising=False)
        monkeypatch.setattr(builtins, "__import__", guarded)

    def test_every_command_works_without_rich(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        capsys.readouterr()
        self._block_rich(monkeypatch)

        assert cli.main(["--database", str(database), "reconcile"]) == cli.EXIT_OK
        capsys.readouterr()
        assert (
            cli.main(
                [
                    "--database",
                    str(database),
                    "why",
                    "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg",
                ]
            )
            == cli.EXIT_OK
        )
        capsys.readouterr()
        assert (
            cli.main(
                [
                    "--database",
                    str(database),
                    "impact",
                    "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg",
                ]
            )
            == cli.EXIT_OK
        )
        capsys.readouterr()
        assert (
            cli.main(["--database", str(database), "simulate", str(FIXTURES / "plan_replace.json")])
            == cli.EXIT_OK
        )
        capsys.readouterr()

    @pytest.mark.parametrize("output", ["text", "json", "yaml", "csv"])
    def test_rich_less_formats_still_render_without_rich(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
        output: str,
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        capsys.readouterr()
        self._block_rich(monkeypatch)
        assert (
            cli.main(["--database", str(database), "reconcile", "--output", output]) == cli.EXIT_OK
        )
        assert capsys.readouterr().out.strip()

    def test_table_output_explains_how_to_install_rich(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        capsys.readouterr()
        self._block_rich(monkeypatch)

        exit_code = cli.main(["--database", str(database), "reconcile", "--output", "table"])
        # A usage error with an actionable message, never a traceback.
        assert exit_code == cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert "rich" in err
        assert "pip install" in err
        assert "Traceback" not in err

    def test_table_still_renders_when_rich_is_installed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pytest.importorskip("rich")
        database = tmp_path / "scan.db"
        cli.main(["--database", str(database), "scan", str(FIXTURES / "state.json")])
        capsys.readouterr()
        assert cli.main(["--database", str(database), "reconcile", "--output", "table"]) == (
            cli.EXIT_OK
        )
        assert capsys.readouterr().out.strip()

    def test_rich_is_not_a_declared_core_dependency(self) -> None:
        """rich must stay optional; only the 'table' and 'dev' extras may name it."""
        import tomllib

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = data["project"]
        assert not any(dep.startswith("rich") for dep in project["dependencies"])
        extras = project["optional-dependencies"]
        assert any(dep.startswith("rich") for dep in extras["table"])
        assert any(dep.startswith("rich") for dep in extras["dev"])

    def test_optional_imports_are_type_check_ignored(self) -> None:
        """Optional, untyped deps must not change mypy's error count.

        Both boto3 and rich are optional and ship no type information. If they
        are not in the mypy overrides, the reported error count depends on which
        extras are installed, and the gate cannot be trusted.
        """
        import tomllib

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        overrides = data["tool"]["mypy"]["overrides"]
        ignored = {module for override in overrides for module in override["module"]}
        assert {"boto3", "rich"} <= ignored
        assert all(override["ignore_missing_imports"] for override in overrides)

    def test_type_check_imports_stay_guarded(self) -> None:
        """rich must appear in reports.py only under TYPE_CHECKING or in _rich()."""
        source = (
            Path(__file__).resolve().parents[2] / "src/reality/services/reports.py"
        ).read_text(encoding="utf-8")
        # A module-scope `from rich...` outside the TYPE_CHECKING block would put
        # rich back in the import chain of every command.
        guarded = source.split("if TYPE_CHECKING:", 1)[1].split("\n\n\n", 1)[0]
        assert "from rich" in guarded
        head = source.split("if TYPE_CHECKING:", 1)[0]
        assert "\nfrom rich" not in head
        # The only runtime import site is the lazy _rich() helper.
        assert source.count("from rich.console import Console") == 2  # TYPE_CHECKING + _rich()
