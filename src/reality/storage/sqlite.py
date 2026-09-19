"""SQLite connection management.

The evidence store is deliberately boring: one local file, foreign keys
strictly on, and transactions begun explicitly so a whole scan is one atomic
unit. Connections run in autocommit mode (``isolation_level=None``); the
:func:`transaction` context manager is the only thing that opens one, which
keeps "one scan = one transaction" true by construction.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a local SQLite connection with foreign keys enforced.

    This store never touches a network resource: ``path`` is a local file
    (or ``:memory:``).
    """
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def foreign_keys_enabled(conn: sqlite3.Connection) -> bool:
    """True when the connection enforces foreign keys (used by tests)."""
    row = conn.execute("PRAGMA foreign_keys").fetchone()
    return bool(row[0])


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """Run a block inside one explicit transaction.

    Commits on success, rolls back on any exception (including
    ``KeyboardInterrupt``). Opening while a transaction is already active
    raises, so nesting is a bug, not a silent join.
    """
    conn.execute("BEGIN")
    try:
        yield
    except BaseException:
        conn.rollback()
        raise
    conn.commit()
