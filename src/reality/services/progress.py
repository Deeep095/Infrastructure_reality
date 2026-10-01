"""Progress reporting for a long-running scan.

A scan against a real account is not instantaneous: it parses local Terraform
documents and then makes a few dozen read-only AWS calls. With no feedback the
only thing the operator can do is wait and wonder whether the process is stuck.

Two rules shape this module:

* **Progress never corrupts a report.** Everything here writes to stderr.
  ``--output json|yaml|csv`` and ``--json`` write to stdout, and a progress
  line landing in the middle of that stream would make it unparseable. Piping
  ``reality scan ... > out.json`` has to keep working.
* **Progress is optional, and silence is the default.** Library callers and the
  test suite get :class:`NullProgressReporter`, so nothing depends on being
  attached to a terminal. ``rich`` stays the optional extra it already is.

Cancellation is *bounded* rather than immediate. A scan is one transaction
(see :meth:`reality.storage.repositories.ScanStore.scan`), so a Ctrl+C during
collection leaves the database untouched instead of half-written. The reporter
therefore only needs to stop cleanly and let the ``KeyboardInterrupt``
propagate; the CLI turns it into a message and a distinct exit code.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from types import TracebackType
from typing import Protocol, TextIO, runtime_checkable

#: How often a plain-text reporter redraws its line, in seconds. Fast enough to
#: look live, slow enough that a redirected log does not fill with thousands of
#: near-identical lines.
REFRESH_SECONDS = 0.2


@runtime_checkable
class ProgressReporter(Protocol):
    """The minimal surface a scan needs to report and cancel."""

    def start(self, total: int, description: str) -> None:
        """Announce a unit of work with ``total`` steps."""

    def advance(self, detail: str = "") -> None:
        """Record one completed step, optionally annotated."""

    def cancelled(self) -> bool:
        """Whether the operator asked to stop."""

    def close(self) -> None:
        """Finish rendering. Must be safe to call twice."""


class NullProgressReporter:
    """Records nothing and cancels nothing. The default for library use.

    Also the right reporter for a non-interactive run: a CI log should show
    the final report, not a spinner that never resolves.
    """

    def start(self, total: int, description: str) -> None:
        """Ignore the work announcement."""

    def advance(self, detail: str = "") -> None:
        """Ignore the completed step."""

    def cancelled(self) -> bool:
        """A silent scan is never cancelled."""
        return False

    def close(self) -> None:
        """Nothing to close."""


class StderrProgressReporter:
    """A dependency-free single-line progress indicator on stderr.

    Used when ``rich`` is not installed. It redraws one line in place on a
    terminal, and degrades to nothing at all when stderr is not a TTY - a
    redirected log should not gain carriage-return noise from a scan.
    """

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        force: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stream: TextIO = stream if stream is not None else sys.stderr
        self._tty = force or bool(getattr(self._stream, "isatty", lambda: False)())
        self._total = 0
        self._done = 0
        self._description = ""
        self._last_draw = 0.0
        self._closed = False
        self._cancelled = False
        # Injectable so the refresh interval can be tested without sleeping.
        self._clock = clock

    def start(self, total: int, description: str) -> None:
        """Show the first frame of the work.

        The first frame counts as a draw, so the immediately following step is
        rate-limited against it rather than against the epoch.
        """
        self._total = total
        self._description = description
        self._last_draw = self._draw(force=True)

    def advance(self, detail: str = "") -> None:
        """Count one step and redraw if the refresh interval has passed.

        The final step always redraws: a progress bar that is cleared before it
        ever shows completion leaves the operator unsure whether the last unit
        of work actually finished.
        """
        self._done += 1
        if detail:
            self._description = detail
        self._last_draw = self._draw(force=self._done >= self._total)

    def cancelled(self) -> bool:
        """A non-interactive reporter has no way to be asked to stop."""
        return self._cancelled

    def close(self) -> None:
        """Clear the line, if one was ever drawn."""
        if self._closed or not self._tty:
            self._closed = True
            return
        self._closed = True
        self._clear()

    def _draw(self, *, force: bool) -> float:
        if not self._tty:
            return self._clock()
        now = self._clock()
        if not force and now - self._last_draw < REFRESH_SECONDS:
            return self._last_draw
        self._clear()
        print(f"\r{self._frame()}", end="", file=self._stream, flush=True)
        return now

    def _frame(self) -> str:
        percent = int(self._done * 100 / self._total) if self._total else 0
        return f"{self._description} [{self._done}/{self._total}] {percent}%"

    def _clear(self) -> None:
        print("\r" + " " * 78 + "\r", end="", file=self._stream, flush=True)


def reporter_for_interactive(*, force: bool = False) -> ProgressReporter:
    """The best reporter the current terminal can support.

    Prefers ``rich`` when it is installed *and* stderr is a terminal, because a
    spinner is easier to read than a hand-drawn percentage. Falls back to
    :class:`StderrProgressReporter`, and finally to silence when stderr is
    redirected, so a piped log stays clean.
    """
    stderr = sys.stderr
    if not force and not bool(getattr(stderr, "isatty", lambda: False)()):
        return NullProgressReporter()
    try:
        from rich.console import Console
        from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
    except ImportError:
        return StderrProgressReporter(stderr)

    console = Console(stderr=True)
    return _RichProgressReporter(console, Progress, BarColumn, TextColumn, TimeElapsedColumn)


class _RichProgressReporter:
    """A ``rich`` spinner/bar, held as a class so the import stays optional.

    ``rich`` is imported inside :func:`reporter_for_interactive`; this class
    only stores the resolved classes, so a core install never touches it.
    """

    def __init__(
        self,
        console: object,
        progress_class: type,
        bar_column: type,
        text_column: type,
        time_column: type,
    ) -> None:
        self._console = console
        self._progress = progress_class(
            text_column("{task.description}"),
            bar_column(),
            text_column("[{task.completed}/{task.total}]"),
            time_column(),
            console=console,
            transient=True,
        )
        self._task: object | None = None
        self._closed = False

    def start(self, total: int, description: str) -> None:
        """Begin a rich task of ``total`` steps."""
        self._progress.start()
        self._task = self._progress.add_task(description, total=total)

    def advance(self, detail: str = "") -> None:
        """Advance the task one step, relabelling it if given a detail."""
        if self._task is None:
            return
        self._progress.update(self._task, advance=1, description=detail or None)

    def cancelled(self) -> bool:
        """rich does not capture Ctrl+C; the CLI handles it."""
        return False

    def close(self) -> None:
        """Stop the task, tolerating a second call."""
        if self._closed:
            return
        self._closed = True
        if self._task is not None:
            self._progress.stop()


class Cancelled(Exception):
    """The operator asked to stop; the scan ended without writing.

    Distinct from an adapter failure: nothing is wrong with the inputs, the
    work simply did not finish, and the database is unchanged.
    """


def guard(reporter: ProgressReporter, total: int, description: str) -> ScanProgress:
    """Context manager yielding a :class:`ScanProgress` step counter.

    Checks for cancellation before each step, so a cancelled scan stops at the
    next source boundary rather than at the end of the whole run - that is
    what makes cancellation *bounded* by one source's work instead of by the
    total.
    """
    return ScanProgress(reporter, total, description)


class ScanProgress:
    """A counted, cancellable unit of work.

    Yields nothing; callers call :meth:`step` after each completed unit.
    """

    def __init__(self, reporter: ProgressReporter, total: int, description: str) -> None:
        self._reporter = reporter
        self._total = total
        self._description = description

    def __enter__(self) -> ScanProgress:
        self._reporter.start(self._total, self._description)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._reporter.close()

    def check(self) -> None:
        """Raise :class:`Cancelled` if the operator asked to stop.

        Called at the top of each unit so a cancelled run does no further
        adapter work.
        """
        if self._reporter.cancelled():
            raise Cancelled("cancelled by operator")

    def step(self, detail: str = "") -> None:
        """Record one completed unit of work."""
        self._reporter.advance(detail)
