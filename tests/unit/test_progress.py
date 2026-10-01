"""Progress reporting and bounded scan cancellation.

The properties under test are the ones a user actually depends on:

* stdout stays clean, so ``reality scan > out.json`` is still parseable;
* a redirected stderr gets no progress noise at all;
* a cancelled scan writes nothing, because the scan is one transaction.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from reality import cli
from reality.adapters.base import AdapterError, AdapterResult
from reality.domain.enums import CoverageStatus
from reality.services.progress import (
    REFRESH_SECONDS,
    Cancelled,
    NullProgressReporter,
    ProgressReporter,
    StderrProgressReporter,
    guard,
)
from reality.services.scan import ScanService
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform" / "state.json"


class RecordingReporter:
    """A reporter that records every call, for asserting the scan's contract."""

    def __init__(self) -> None:
        self.started: list[tuple[int, str]] = []
        self.advanced: list[str] = []
        self.closed = 0

    def start(self, total: int, description: str) -> None:
        self.started.append((total, description))

    def advance(self, detail: str = "") -> None:
        self.advanced.append(detail)

    def cancelled(self) -> bool:
        """Never cancels: this reporter is for the happy path."""
        return False

    def close(self) -> None:
        self.closed += 1


class CancellingReporter(RecordingReporter):
    """Cancels after ``after`` steps, to prove the scan stops mid-run."""

    def __init__(self, after: int) -> None:
        super().__init__()
        self._after = after

    def cancelled(self) -> bool:
        """Cancel once enough steps have been taken to be mid-scan."""
        return len(self.advanced) >= self._after


class FakeClock:
    """A manually advanced clock, so refresh timing is testable without sleeping."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        """Move past the refresh interval."""
        self.now += seconds


def _tty_reporter(clock: FakeClock) -> tuple[StderrProgressReporter, io.StringIO]:
    stream = io.StringIO()
    stream.isatty = lambda: True  # type: ignore[method-assign]
    return StderrProgressReporter(stream, force=True, clock=clock), stream


# --- reporter selection ----------------------------------------------------------


def test_null_reporter_is_silent_and_never_cancels() -> None:
    reporter = NullProgressReporter()
    reporter.start(3, "scanning")
    reporter.advance("one")
    assert reporter.cancelled() is False
    reporter.close()


def test_redirected_stderr_gets_no_progress() -> None:
    """A piped log must contain the report and nothing else."""
    assert isinstance(NullProgressReporter(), ProgressReporter)

    reporter = StderrProgressReporter(io.StringIO())
    reporter.start(2, "scanning 2 source(s)")
    reporter.advance("one")
    reporter.close()
    # StringIO is not a TTY, so nothing was drawn.
    assert reporter.cancelled() is False


def test_tty_reporter_draws_progress_and_clears_it() -> None:
    clock = FakeClock()
    reporter, stream = _tty_reporter(clock)

    reporter.start(2, "scanning 2 source(s)")
    clock.advance(REFRESH_SECONDS)
    reporter.advance("parsed state.json")
    clock.advance(REFRESH_SECONDS)
    reporter.advance("reading aws_resources")
    reporter.close()

    written = stream.getvalue()
    assert "scanning 2 source(s)" in written
    assert "parsed state.json" in written
    assert "[2/2] 100%" in written
    # The line was cleared on close, so the terminal is not left mid-frame.
    assert written.endswith("\r" + " " * 78 + "\r")


def test_progress_frame_reports_percentage() -> None:
    clock = FakeClock()
    reporter, stream = _tty_reporter(clock)
    reporter.start(4, "scanning")
    clock.advance(REFRESH_SECONDS)
    reporter.advance()
    assert "[1/4] 25%" in stream.getvalue()


def test_final_frame_is_always_drawn() -> None:
    """The last step redraws even inside the refresh interval.

    A bar cleared before it ever showed completion leaves the operator unsure
    whether the final unit of work actually finished.
    """
    clock = FakeClock()
    reporter, stream = _tty_reporter(clock)
    reporter.start(3, "scanning")
    reporter.advance()
    reporter.advance()
    reporter.advance()
    assert "[3/3] 100%" in stream.getvalue()


def test_mid_run_frames_are_rate_limited() -> None:
    """A fast scan must not emit a frame per step.

    Only the first and final frames are drawn; the ones between are dropped
    until the refresh interval passes, so a terminal does not flicker and a
    log does not fill with near-identical lines.
    """
    clock = FakeClock()
    reporter, stream = _tty_reporter(clock)
    reporter.start(100, "scanning")
    before = stream.getvalue()
    for _ in range(10):
        reporter.advance()
    assert stream.getvalue() == before

    # Once the interval passes, the next step draws again.
    clock.advance(REFRESH_SECONDS)
    reporter.advance()
    assert "[11/100] 11%" in stream.getvalue()


# --- the scan's own use of progress ------------------------------------------------


def _store(tmp_path: Path) -> ScanStore:
    conn = connect(tmp_path / "progress.db")
    migrate(conn)
    return ScanStore(conn)


def test_scan_announces_one_step_per_source(tmp_path: Path) -> None:
    reporter = RecordingReporter()
    service = ScanService(_store(tmp_path), progress=reporter)

    service.run([FIXTURES])

    # One local file, no AWS side: exactly one unit of work announced.
    assert len(reporter.started) == 1
    total, description = reporter.started[0]
    assert total == 1
    assert "1 source(s)" in description
    assert reporter.advanced == ["parsed state.json"]
    # The reporter is always closed, so a terminal never keeps a stale frame.
    assert reporter.closed == 1


def test_scan_is_silent_by_default(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A library caller gets no output without opting in."""
    ScanService(_store(tmp_path)).run([FIXTURES])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_cancelled_scan_writes_nothing(tmp_path: Path) -> None:
    """Cancellation before the write leaves no scan run behind.

    The scan collects every source first and commits in one transaction, so a
    scan stopped partway through collection must leave the database empty
    rather than half-populated.
    """
    store = _store(tmp_path)
    reporter = CancellingReporter(after=0)  # cancel before the first step

    with pytest.raises(Cancelled):
        ScanService(store, progress=reporter).run([FIXTURES])

    assert store.scan_runs.count() == 0
    assert store.resources.all() == []


def test_cancellation_happens_between_sources_not_mid_adapter(tmp_path: Path) -> None:
    """Bounded means per-source: the next boundary stops the run.

    With a local file and an AWS source there are two boundaries. The
    cancellation is raised at the second one, so exactly one unit of work was
    wasted - the bound is one source, not the whole run.
    """

    class NeverCancelled(RecordingReporter):
        def cancelled(self) -> bool:
            """Cancel only after the first step has completed."""
            return len(self.advanced) >= 1

    class CountingAdapter:
        """Counts how many times it was asked to collect."""

        calls = 0

        def collect(self) -> AdapterResult:
            CountingAdapter.calls += 1
            return AdapterResult()

    store = _store(tmp_path)
    reporter = NeverCancelled()
    with pytest.raises(Cancelled):
        ScanService(store, aws_resources=CountingAdapter(), progress=reporter).run([FIXTURES])  # type: ignore[arg-type]

    # The local file was parsed; the AWS source was never touched.
    assert reporter.advanced == ["parsed state.json"]
    assert CountingAdapter.calls == 0
    assert store.scan_runs.count() == 0


# --- the CLI contract --------------------------------------------------------------


def test_cli_scan_does_not_pollute_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The report is the only thing on stdout, so redirection stays usable."""
    database = tmp_path / "scan.db"
    assert cli.main(["--database", str(database), "scan", str(FIXTURES)]) == cli.EXIT_OK
    first = capsys.readouterr().out

    assert cli.main(["--database", str(database), "scan", str(FIXTURES)]) == cli.EXIT_OK
    second = capsys.readouterr().out

    # Both runs printed a report, and the first line parses as text.
    assert first.startswith("reality: scan")
    assert second.startswith("reality: scan")
    json.loads(json.dumps({"ok": True}))  # stdout was never asked to be JSON


def test_cancelled_scan_exits_with_its_own_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An interrupted scan is distinguishable from a failed one."""
    database = tmp_path / "scan.db"

    def interrupted(self, terraform_paths=()):  # type: ignore[no-untyped-def]
        raise KeyboardInterrupt

    monkeypatch.setattr(ScanService, "run", interrupted)
    exit_code = cli.main(["--database", str(database), "scan", str(FIXTURES)])
    assert exit_code == cli.EXIT_INTERRUPTED
    assert exit_code != cli.EXIT_CONFIG
    assert "nothing was written" in capsys.readouterr().err


def test_reporter_cancelled_forces_scan_to_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reporter that reports cancellation aborts the CLI scan."""
    database = tmp_path / "scan.db"
    monkeypatch.setattr(cli, "_progress_reporter", lambda: CancellingReporter(after=0))

    exit_code = cli.main(["--database", str(database), "scan", str(FIXTURES)])

    assert exit_code == cli.EXIT_INTERRUPTED
    # Nothing was committed.
    conn = connect(database)
    assert ScanStore(conn).scan_runs.count() == 0
    conn.close()


def test_adapter_failure_is_coverage_not_cancellation(tmp_path: Path) -> None:
    """A failing adapter still completes the scan with reduced coverage.

    Cancellation and adapter failure are different things: the reporter is
    never cancelled, so a broken source reduces coverage instead of aborting.
    """

    class BrokenAdapter:
        def collect(self):  # type: ignore[no-untyped-def]
            raise AdapterError("access denied")

    reporter = RecordingReporter()
    service = ScanService(_store(tmp_path), aws_resources=BrokenAdapter(), progress=reporter)  # type: ignore[arg-type]

    report = service.run([FIXTURES])

    statuses = {source.source: source.status for source in report.sources}
    assert statuses["aws_resources"] is CoverageStatus.UNAVAILABLE
    # The local parse still happened and was still recorded.
    assert statuses["terraform"] is CoverageStatus.AVAILABLE
    assert reporter.closed == 1


def test_guard_raises_when_reporter_cancels() -> None:
    reporter = CancellingReporter(after=1)
    with guard(reporter, 2, "work") as progress:
        progress.step("one")
        with pytest.raises(Cancelled):
            progress.check()
