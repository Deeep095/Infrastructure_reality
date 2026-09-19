"""Explicit, versioned schema migrations for the evidence store.

Migrations are an ordered tuple of :class:`Migration` records applied inside
a single transaction; the applied version lives in ``PRAGMA user_version``
and the history in the ``schema_metadata`` table. Every statement is written
idempotently (``IF NOT EXISTS`` / ``INSERT OR REPLACE``) so re-applying a
migration, or resuming a database left at an older version, is safe.

Current schema (version 3):

- ``scan_runs``         one row per scan, the anchor for everything below
- ``resources``         keyed by canonical ID; ``discovered_at`` never rewritten
- ``evidence``          keyed by evidence ID; raw payloads only when supplied
- ``relationships``     keyed by (source, target, type, origin); temporal
- ``relationship_evidence``  join table, FK-enforced both sides
- ``coverage``          what could and could not be consulted per scan
- ``terraform_addresses``    declared Terraform resources and plan actions
- ``findings``          reconciliation conclusions, evidence linked as JSON
- ``identity_mappings`` evidence-backed terraform↔aws identity joins
- ``schema_metadata``   migration history

Deliberate choices: ``relationships`` does not foreign-key onto ``resources``
because a relationship may target an unresolved external reference that has
no resource row; ``relationship_evidence`` is where referential integrity is
enforced. No column anywhere stores credentials, profiles, or secrets — the
store holds discovery results only (see docs/safety.md).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from reality.storage.sqlite import transaction

LATEST_VERSION = 3


@dataclass(frozen=True)
class Migration:
    """One schema step: a version number, a name, and its statements."""

    version: int
    name: str
    statements: tuple[str, ...]


_V1_TABLES: tuple[str, ...] = (
    """
    CREATE TABLE schema_metadata (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE scan_runs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        source      TEXT NOT NULL,
        region      TEXT,
        account     TEXT,
        started_at  TEXT NOT NULL,
        finished_at TEXT
    )
    """,
    """
    CREATE TABLE resources (
        canonical_id       TEXT PRIMARY KEY,
        resource_type      TEXT NOT NULL,
        provider           TEXT NOT NULL,
        native_id          TEXT,
        arn                TEXT,
        terraform_address  TEXT,
        region             TEXT,
        account            TEXT,
        name               TEXT,
        discovered_at      TEXT NOT NULL,
        source             TEXT,
        scan_run_id        INTEGER REFERENCES scan_runs(id)
    )
    """,
    """
    CREATE TABLE evidence (
        id                  TEXT PRIMARY KEY,
        source              TEXT NOT NULL,
        type                TEXT NOT NULL,
        observed_at         TEXT,
        actor               TEXT,
        source_ref          TEXT NOT NULL,
        target_ref          TEXT NOT NULL,
        source_canonical_id TEXT,
        target_canonical_id TEXT,
        strength            TEXT NOT NULL,
        raw_locator         TEXT NOT NULL,
        explanation         TEXT NOT NULL,
        raw_json            TEXT,
        scan_run_id         INTEGER REFERENCES scan_runs(id)
    )
    """,
    """
    CREATE TABLE relationships (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        source_canonical_id TEXT NOT NULL,
        target_canonical_id TEXT NOT NULL,
        type               TEXT NOT NULL,
        origin             TEXT NOT NULL,
        first_seen_at      TEXT,
        last_seen_at       TEXT
    )
    """,
    """
    CREATE UNIQUE INDEX ux_relationships_identity
        ON relationships (source_canonical_id, target_canonical_id, type, origin)
    """,
    """
    CREATE TABLE relationship_evidence (
        relationship_id INTEGER NOT NULL REFERENCES relationships(id) ON DELETE CASCADE,
        evidence_id     TEXT NOT NULL REFERENCES evidence(id),
        PRIMARY KEY (relationship_id, evidence_id)
    )
    """,
    """
    CREATE TABLE coverage (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        source       TEXT NOT NULL,
        status       TEXT NOT NULL,
        reason       TEXT NOT NULL,
        region       TEXT,
        recorded_at  TEXT NOT NULL,
        scan_run_id  INTEGER REFERENCES scan_runs(id)
    )
    """,
    """
    CREATE TABLE terraform_addresses (
        address          TEXT PRIMARY KEY,
        tf_resource_type TEXT NOT NULL,
        actions_json     TEXT NOT NULL,
        canonical_id     TEXT,
        scan_run_id      INTEGER REFERENCES scan_runs(id)
    )
    """,
    """
    CREATE TABLE findings (
        id                      TEXT PRIMARY KEY,
        subject_canonical_id    TEXT NOT NULL,
        conclusion              TEXT NOT NULL,
        explanation             TEXT NOT NULL,
        evidence_ids_json       TEXT NOT NULL DEFAULT '[]',
        unavailable_sources_json TEXT NOT NULL DEFAULT '[]',
        scan_run_id             INTEGER REFERENCES scan_runs(id)
    )
    """,
)

_V2_INDEXES: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS ix_relationships_source ON relationships (source_canonical_id)",
    "CREATE INDEX IF NOT EXISTS ix_relationships_target ON relationships (target_canonical_id)",
    "CREATE INDEX IF NOT EXISTS ix_evidence_source_canonical ON evidence (source_canonical_id)",
    "CREATE INDEX IF NOT EXISTS ix_evidence_target_canonical ON evidence (target_canonical_id)",
    "CREATE INDEX IF NOT EXISTS ix_resources_account ON resources (account)",
    "CREATE INDEX IF NOT EXISTS ix_findings_subject ON findings (subject_canonical_id)",
)

# Version 3: evidence-backed identity mappings (the terraform↔aws join), plus
# the scan-run indexes the snapshot-scoped reconciliation reads need. The
# mapping's evidence_id is FK-enforced: a mapping without its backing evidence
# row cannot exist.
_V3_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE identity_mappings (
        terraform_canonical_id TEXT NOT NULL,
        aws_canonical_id       TEXT NOT NULL,
        basis                  TEXT NOT NULL,
        matched_value          TEXT NOT NULL,
        evidence_id            TEXT NOT NULL REFERENCES evidence(id),
        reason                 TEXT NOT NULL,
        scan_run_id            INTEGER REFERENCES scan_runs(id),
        PRIMARY KEY (terraform_canonical_id, aws_canonical_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_evidence_scan_run ON evidence (scan_run_id)",
    "CREATE INDEX IF NOT EXISTS ix_coverage_scan_run ON coverage (scan_run_id)",
    "CREATE INDEX IF NOT EXISTS ix_identity_mappings_scan_run ON identity_mappings (scan_run_id)",
)

MIGRATIONS: tuple[Migration, ...] = (
    Migration(version=1, name="base schema", statements=_V1_TABLES),
    Migration(version=2, name="lookup indexes", statements=_V2_INDEXES),
    Migration(version=3, name="identity mappings", statements=_V3_STATEMENTS),
)


def current_version(conn: sqlite3.Connection) -> int:
    """The schema version currently applied to this database."""
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0])


def migrate(conn: sqlite3.Connection, migrations: Sequence[Migration] = MIGRATIONS) -> int:
    """Apply pending migrations in order; return the resulting version.

    Safe to call repeatedly: already-applied migrations are skipped, and each
    migration runs inside one transaction, so a failure leaves the database
    at its previous version.
    """
    with transaction(conn):
        version = current_version(conn)
        now = datetime.now(UTC).isoformat()
        for migration in migrations:
            if migration.version <= version:
                continue
            for statement in migration.statements:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {migration.version}")
            conn.execute(
                "INSERT OR REPLACE INTO schema_metadata (key, value, applied_at) VALUES (?, ?, ?)",
                (f"migration:{migration.version}", migration.name, now),
            )
        latest = max((m.version for m in migrations), default=version)
        conn.execute(
            "INSERT OR REPLACE INTO schema_metadata (key, value, applied_at) "
            "VALUES ('schema_version', ?, ?)",
            (str(latest), now),
        )
    return current_version(conn)
