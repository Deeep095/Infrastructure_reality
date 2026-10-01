"""Diagnostics: report whether this machine can do what the user is asking for.

``reality doctor`` exists because the failure modes of a read-only AWS auditor
are all environmental and all confusing in different ways: a missing extra, a
typo in a profile name, a database from an older schema, credentials that
expired overnight. Each one surfaces as a confusing error much later, in the
middle of a command. The doctor moves that discovery to the front, where the
remedy can be printed next to the problem.

Two rules shape it:

* **It diagnoses, it does not fix.** No writes, no ``pip install``, no ``aws
  sso login``. It says what is wrong and what to run.
* **It contacts nothing without the usual explicit opt-in.** Without
  ``--aws --profile --region`` it reports the opt-in state and stops. A
  diagnostic command that quietly reached STS would undermine the guarantee
  every other command makes.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reality.config import RealityConfig
from reality.settings import (
    Check,
    _aws_checks,
    _database_check,
    _optional_dependency_checks,
    _package_check,
    _python_check,
    _settings_check,
    _terraform_check,
    config_path,
)


class DoctorReport(BaseModel):
    """The checks that ran, and the one number a script cares about."""

    model_config = ConfigDict(frozen=True)

    checks: tuple[Check, ...]
    settings_path: Path

    @property
    def failures(self) -> tuple[Check, ...]:
        """Checks that make the environment unusable as configured."""
        return tuple(check for check in self.checks if check.failed)

    @property
    def healthy(self) -> bool:
        """True when nothing failed; warnings and skips still pass.

        A warning is advice, not a defect: no optional extra installed, or a
        database with no scans yet, both leave the tool usable.
        """
        return not self.failures


def run_doctor(
    config: RealityConfig,
    *,
    settings_path: Path | None = None,
) -> DoctorReport:
    """Run every applicable check and return the report.

    Settings and the database are always inspected. The AWS checks depend on
    the opt-in triple exactly as a real scan's would, so a green doctor means
    the same thing a green scan would.
    """
    path = settings_path or config_path()
    checks: list[Check] = [_python_check(), _package_check()]
    checks.extend(_optional_dependency_checks())
    checks.append(_settings_check(path))
    checks.append(_database_check(config.database_path))
    checks.extend(
        _aws_checks(
            opt_in=config.aws_opt_in,
            profile=config.aws_profile,
            region=config.aws_region,
        )
    )
    checks.append(_terraform_check())
    return DoctorReport(checks=tuple(checks), settings_path=path)


def render_doctor(report: DoctorReport) -> str:
    """Render the report as plain text, one line per check.

    Status words are padded rather than coloured so the output stays readable
    when piped, and the remedy is on the same line as the problem it fixes.
    """
    glyphs = {"ok": "  ok  ", "warn": " warn ", "fail": " FAIL ", "skip": " skip "}
    lines = [f"reality: doctor (settings: {report.settings_path})"]
    for check in report.checks:
        line = f"{glyphs[check.status]} {check.name:<12} {check.detail}"
        lines.append(line)
        if check.remedy and check.status != "ok":
            lines.append(f"         -> {check.remedy}")
    lines.append("")
    if report.failures:
        failed = ", ".join(check.name for check in report.failures)
        lines.append(f"reality: {len(report.failures)} check(s) failed: {failed}")
    else:
        lines.append("reality: environment looks usable")
    return "\n".join(lines) + "\n"
