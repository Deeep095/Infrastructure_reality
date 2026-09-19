"""Tests for the SQLite layer: connections, migrations, foreign keys, transactions."""

from __future__ import annotations

import sqlite3

import pytest

from reality.storage.migrations import MIGRATIONS, current_version, migrate
from reality.storage.sqlite import connect, foreign_keys_enabled, transaction

EXPECTED_TABLES = {
    "scan_runs",
    "resources",
    "evidence",
    "relationships",
    "relationship_evidence",
    "coverage",
    "terraform_addresses",
    "findings",
    "identity_mappings",
    "schema_metadata",
}


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "evidence.db"


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {row["name"] for row in rows}


def _index_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    return {row["name"] for row in rows}


# --- connection -------------------------------------------------------------


def test_connect_enables_foreign_keys(db_path) -> None:
    conn = connect(db_path)
    assert foreign_keys_enabled(conn) is True


def test_connect_reuses_the_same_file(db_path) -> None:
    with connect(db_path) as conn:
        migrate(conn)
    with connect(db_path) as conn2:
        assert _table_names(conn2) >= EXPECTED_TABLES


# --- migrations -------------------------------------------------------------


def test_migrate_creates_all_tables(db_path) -> None:
    conn = connect(db_path)
    version = migrate(conn)
    assert version == 3
    assert current_version(conn) == 3
    assert _table_names(conn) >= EXPECTED_TABLES


def test_migrate_is_idempotent(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)
    metadata_rows = conn.execute("SELECT COUNT(*) FROM schema_metadata").fetchone()[0]
    migrate(conn)  # second run must be a no-op
    assert current_version(conn) == 3
    assert conn.execute("SELECT COUNT(*) FROM schema_metadata").fetchone()[0] == metadata_rows


def test_migrate_resumes_from_partial_version(db_path) -> None:
    conn = connect(db_path)
    migrate(conn, MIGRATIONS[:1])  # apply only the base schema
    assert current_version(conn) == 1
    migrate(conn)  # resume: migrations 2 and 3 apply
    assert current_version(conn) == 3
    assert "ix_relationships_source" in _index_names(conn)
    assert "identity_mappings" in _table_names(conn)


def test_migrate_records_history_in_schema_metadata(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)
    rows = dict(conn.execute("SELECT key, value FROM schema_metadata").fetchall())
    assert rows["migration:1"] == "base schema"
    assert rows["migration:2"] == "lookup indexes"
    assert rows["migration:3"] == "identity mappings"
    assert rows["schema_version"] == "3"


def test_migration_failure_leaves_database_at_previous_version(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)

    from reality.storage.migrations import Migration

    broken = Migration(version=4, name="broken", statements=("CREATE TABLE broken (",))
    with pytest.raises(sqlite3.OperationalError):
        migrate(conn, (*MIGRATIONS, broken))
    assert current_version(conn) == 3  # rolled back, not half-applied
    assert "broken" not in _table_names(conn)


# --- foreign keys -----------------------------------------------------------


def test_foreign_keys_reject_evidence_link_to_missing_evidence(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)
    cursor = conn.execute(
        "INSERT INTO relationships (source_canonical_id, target_canonical_id, type, origin) "
        "VALUES ('a', 'b', 'depends_on', 'terraform_declared')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO relationship_evidence (relationship_id, evidence_id) VALUES (?, ?)",
            (cursor.lastrowid, "ev-does-not-exist"),
        )


def test_foreign_keys_reject_resource_with_missing_scan_run(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO resources (canonical_id, resource_type, provider, "
            "discovered_at, scan_run_id) "
            "VALUES ('x', 'ec2_instance', 'aws', '2026-01-01T00:00:00+00:00', 999)"
        )


def test_foreign_keys_reject_finding_link_columns_where_enforced(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)
    # evidence.scan_run_id is FK-enforced too
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO evidence (id, source, type, source_ref, target_ref, strength, "
            "raw_locator, explanation, scan_run_id) "
            "VALUES ('e1', 'iam', 'policy_statement', 'a', 'b', 'low', 'loc', 'why', 424)"
        )


# --- transactions -----------------------------------------------------------


INSERT_SCAN_RUN = (
    "INSERT INTO scan_runs (source, started_at) "
    "VALUES ('aws_resources', '2026-01-01T00:00:00+00:00')"
)


def test_transaction_commits_on_success(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)
    with transaction(conn):
        conn.execute(INSERT_SCAN_RUN)
    assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 1


def test_transaction_rolls_back_on_error(db_path) -> None:
    conn = connect(db_path)
    migrate(conn)

    class Boom(Exception):
        pass

    with pytest.raises(Boom), transaction(conn):
        conn.execute(INSERT_SCAN_RUN)
        raise Boom()
    assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0


def test_transaction_rolls_back_ddl(db_path) -> None:
    # DDL is transactional in SQLite; a failed migration leaves no trace.
    conn = connect(db_path)
    migrate(conn)

    class Boom(Exception):
        pass

    with pytest.raises(Boom), transaction(conn):
        conn.execute("CREATE TABLE stray (id INTEGER)")
        raise Boom()
    assert "stray" not in _table_names(conn)
