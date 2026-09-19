"""Local SQLite persistence for the reality evidence store."""

from reality.storage.migrations import MIGRATIONS, Migration, current_version, migrate
from reality.storage.repositories import (
    EvidenceRecord,
    ResourceContext,
    ScanSession,
    ScanStore,
)
from reality.storage.sqlite import connect, foreign_keys_enabled, transaction

__all__ = [
    "EvidenceRecord",
    "MIGRATIONS",
    "Migration",
    "ResourceContext",
    "ScanSession",
    "ScanStore",
    "connect",
    "current_version",
    "foreign_keys_enabled",
    "migrate",
    "transaction",
]
