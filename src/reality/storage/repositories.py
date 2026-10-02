"""Repositories for the evidence store.

Semantics held everywhere in this module:

- **Idempotent upserts keyed by identity** — canonical ID for resources,
  evidence ID for evidence, (source, target, type, origin) for
  relationships, address for Terraform declarations, the identity pair for
  identity mappings, finding ID for findings. Writing the same fact twice
  leaves one row in the same state.
- **Temporal fields are protected.** ``first_seen_at`` is never overwritten
  once set; ``last_seen_at`` advances only with a strictly later
  observation; ``discovered_at`` is fixed at first insert.
- **Raw payloads are opt-in.** Event/policy JSON is stored only when the
  caller supplies it. Nothing here writes credentials, profile names, or
  secrets — there are no such columns.
- **One scan, one transaction** via :meth:`ScanStore.scan`.

Reconstruction into domain models is exact: datetimes round trip as
timezone-aware ISO strings, enums as their values, tuples as JSON arrays.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from reality.domain.enums import (
    ChangeAction,
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    MappingBasis,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.models import (
    Coverage,
    Evidence,
    Finding,
    IdentityMapping,
    Relationship,
    Resource,
    TerraformChange,
)
from reality.storage.sqlite import transaction

if TYPE_CHECKING:
    from reality.services.graph import IdentityResolver


def _resolve_stored(resolver: IdentityResolver, canonical_id: str) -> str | None:
    """The first stored ID compatible with ``canonical_id``, or ``None``."""
    for candidate in resolver.resolve(canonical_id):
        if resolver.is_stored(candidate):
            return candidate
    return None


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _dump_json_list(values: Sequence[str]) -> str:
    return json.dumps(list(values))


def _load_json_list(raw: str) -> tuple[str, ...]:
    return tuple(json.loads(raw))


class EvidenceRecord(BaseModel):
    """An evidence item plus its optional raw payload, as stored."""

    model_config = ConfigDict(frozen=True)

    evidence: Evidence
    raw_payload: dict[str, Any] | None = None


class ResourceContext(BaseModel):
    """Everything the ``why``/``impact`` commands need for one resource."""

    model_config = ConfigDict(frozen=True)

    resource: Resource
    outgoing: tuple[Relationship, ...] = ()
    incoming: tuple[Relationship, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()
    coverage: tuple[Coverage, ...] = ()


# --- scan runs --------------------------------------------------------------


class ScanRunRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def create(
        self,
        *,
        source: EvidenceSource,
        region: str | None = None,
        account: str | None = None,
        started_at: datetime | None = None,
    ) -> int:
        """Insert a scan-run row and return its ID."""
        cursor = self._conn.execute(
            "INSERT INTO scan_runs (source, region, account, started_at) VALUES (?, ?, ?, ?)",
            (source.value, region, account, (started_at or datetime.now(UTC)).isoformat()),
        )
        if cursor.lastrowid is None:  # pragma: no cover - sqlite always sets this
            raise sqlite3.IntegrityError("scan run insert produced no row id")
        return cursor.lastrowid

    def finish(self, scan_run_id: int, finished_at: datetime | None = None) -> None:
        self._conn.execute(
            "UPDATE scan_runs SET finished_at = ? WHERE id = ?",
            ((finished_at or datetime.now(UTC)).isoformat(), scan_run_id),
        )

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0])

    def latest_discovery_run(self) -> int | None:
        """The most recent scan run that collected evidence - not a
        reconciliation pass.

        The snapshot boundary for analysis: everything a reconciliation pass
        evaluates is anchored to one scan run, and that run must be one that
        actually collected something rather than a pass that only wrote
        conclusions.
        """
        row = self._conn.execute(
            "SELECT id FROM scan_runs WHERE source != ? ORDER BY id DESC LIMIT 1",
            (EvidenceSource.RECONCILIATION.value,),
        ).fetchone()
        return int(row["id"]) if row is not None else None

    def latest_reconciliation_run(self) -> int | None:
        """The most recent reconciliation pass.

        Reconciliation passes store their findings in their own scan run, so
        to access the latest conclusions we need the reconciliation run, not
        the discovery run it analysed.
        """
        row = self._conn.execute(
            "SELECT id FROM scan_runs WHERE source = ? ORDER BY id DESC LIMIT 1",
            (EvidenceSource.RECONCILIATION.value,),
        ).fetchone()
        return int(row["id"]) if row is not None else None

    def get_source(self, scan_run_id: int) -> EvidenceSource | None:
        """Which source anchored one scan run, or ``None`` if it does not exist."""
        row = self._conn.execute(
            "SELECT source FROM scan_runs WHERE id = ?", (scan_run_id,)
        ).fetchone()
        return EvidenceSource(row["source"]) if row is not None else None


# --- resources --------------------------------------------------------------


class ResourceRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, resource: Resource, scan_run_id: int | None = None) -> None:
        """Insert or merge a resource keyed by canonical ID.

        ``discovered_at`` is fixed at first insert (never rewritten).
        Descriptive fields merge: a later upsert may fill in fields that
        were ``None`` but never blanks one that is already set.

        ``scan_run_id`` is the run that most recently observed this resource,
        which is what makes snapshot-scoped reads (``for_scan_run``) answer
        "what did *this* scan see?". ``discovered_at`` already carries
        first-seen, so keeping the original run here instead would make every
        re-observation invisible to the scan that performed it.
        """
        self._conn.execute(
            """
            INSERT INTO resources (
                canonical_id, resource_type, provider, native_id, arn,
                terraform_address, region, account, name, discovered_at,
                source, scan_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (canonical_id) DO UPDATE SET
                native_id         = COALESCE(excluded.native_id, resources.native_id),
                arn               = COALESCE(excluded.arn, resources.arn),
                terraform_address = COALESCE(
                    excluded.terraform_address, resources.terraform_address
                ),
                region            = COALESCE(resources.region, excluded.region),
                account           = COALESCE(resources.account, excluded.account),
                name              = COALESCE(excluded.name, resources.name),
                source            = COALESCE(excluded.source, resources.source),
                scan_run_id       = COALESCE(excluded.scan_run_id, resources.scan_run_id)
            """,
            (
                resource.canonical_id,
                resource.resource_type.value,
                resource.provider,
                resource.native_id,
                resource.arn,
                resource.terraform_address,
                resource.region,
                resource.account,
                resource.name,
                resource.discovered_at.isoformat(),
                resource.source.value if resource.source else None,
                scan_run_id,
            ),
        )

    def get(self, canonical_id: str) -> Resource | None:
        row = self._conn.execute(
            "SELECT * FROM resources WHERE canonical_id = ?", (canonical_id,)
        ).fetchone()
        return self._hydrate(row) if row is not None else None

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM resources").fetchone()[0])

    def all_canonical_ids(self) -> list[str]:
        """Return all canonical IDs in the database."""
        rows = self._conn.execute("SELECT canonical_id FROM resources").fetchall()
        return [row["canonical_id"] for row in rows]

    def all(self) -> list[Resource]:
        """Every stored resource, hydrated, in canonical-ID order.

        Callers that match a user-supplied identifier against the
        source-native fields need the whole row, not just the key.
        """
        rows = self._conn.execute("SELECT * FROM resources ORDER BY canonical_id").fetchall()
        return [self._hydrate(row) for row in rows]

    def for_scan_run(self, scan_run_id: int) -> tuple[Resource, ...]:
        """Resources that were observed or declared in a specific scan run.

        A resource belongs to a scan run if it was upserted during that run.
        """
        rows = self._conn.execute(
            "SELECT * FROM resources WHERE scan_run_id = ? ORDER BY canonical_id",
            (scan_run_id,),
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    @staticmethod
    def _hydrate(row: sqlite3.Row) -> Resource:
        return Resource(
            canonical_id=row["canonical_id"],
            resource_type=ResourceType(row["resource_type"]),
            provider=row["provider"],
            native_id=row["native_id"],
            arn=row["arn"],
            terraform_address=row["terraform_address"],
            region=row["region"],
            account=row["account"],
            name=row["name"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            source=EvidenceSource(row["source"]) if row["source"] else None,
        )


# --- evidence ---------------------------------------------------------------


class EvidenceRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(
        self,
        evidence: Evidence,
        raw_payload: dict[str, Any] | None = None,
        scan_run_id: int | None = None,
    ) -> None:
        """Insert or refresh an evidence item keyed by its ID.

        ``raw_payload`` is stored as JSON only when supplied; ``None``
        leaves the column NULL rather than writing ``"null"``.
        """
        self._conn.execute(
            """
            INSERT INTO evidence (
                id, source, type, observed_at, actor, source_ref, target_ref,
                source_canonical_id, target_canonical_id, strength,
                raw_locator, explanation, raw_json, scan_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET
                source              = excluded.source,
                type                = excluded.type,
                observed_at         = excluded.observed_at,
                actor               = excluded.actor,
                source_ref          = excluded.source_ref,
                target_ref          = excluded.target_ref,
                source_canonical_id = excluded.source_canonical_id,
                target_canonical_id = excluded.target_canonical_id,
                strength            = excluded.strength,
                raw_locator         = excluded.raw_locator,
                explanation         = excluded.explanation,
                raw_json            = COALESCE(excluded.raw_json, evidence.raw_json),
                scan_run_id         = COALESCE(excluded.scan_run_id, evidence.scan_run_id)
            """,
            (
                evidence.id,
                evidence.source.value,
                evidence.type.value,
                _dt(evidence.observed_at),
                evidence.actor,
                evidence.source_ref,
                evidence.target_ref,
                evidence.source_canonical_id,
                evidence.target_canonical_id,
                evidence.strength.value,
                evidence.raw_locator,
                evidence.explanation,
                json.dumps(raw_payload) if raw_payload is not None else None,
                scan_run_id,
            ),
        )

    def get(self, evidence_id: str) -> Evidence | None:
        row = self._conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return self._hydrate(row) if row is not None else None

    def get_record(self, evidence_id: str) -> EvidenceRecord | None:
        """Evidence plus its raw payload, for reports that show the source."""
        row = self._conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row is None:
            return None
        raw = json.loads(row["raw_json"]) if row["raw_json"] is not None else None
        return EvidenceRecord(evidence=self._hydrate(row), raw_payload=raw)

    def ids_referencing(self, canonical_id: str) -> tuple[str, ...]:
        rows = self._conn.execute(
            "SELECT id FROM evidence WHERE source_canonical_id = ? OR target_canonical_id = ?",
            (canonical_id, canonical_id),
        ).fetchall()
        return tuple(row["id"] for row in rows)

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])

    @staticmethod
    def _hydrate(row: sqlite3.Row) -> Evidence:
        return Evidence(
            id=row["id"],
            source=EvidenceSource(row["source"]),
            type=EvidenceType(row["type"]),
            observed_at=_parse_dt(row["observed_at"]),
            actor=row["actor"],
            source_ref=row["source_ref"],
            target_ref=row["target_ref"],
            source_canonical_id=row["source_canonical_id"],
            target_canonical_id=row["target_canonical_id"],
            strength=EvidenceStrength(row["strength"]),
            raw_locator=row["raw_locator"],
            explanation=row["explanation"],
        )


# --- relationships ----------------------------------------------------------


class RelationshipRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, relationship: Relationship) -> int:
        """Insert or advance a relationship keyed by its identity.

        Temporal contract: ``first_seen_at`` is kept once set (an earlier
        candidate never rewrites it); ``last_seen_at`` moves only to a
        strictly later timestamp. Returns the stable row ID.
        """
        self._conn.execute(
            """
            INSERT INTO relationships (
                source_canonical_id, target_canonical_id, type, origin,
                first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (source_canonical_id, target_canonical_id, type, origin) DO UPDATE SET
                first_seen_at = CASE
                    WHEN relationships.first_seen_at IS NOT NULL THEN relationships.first_seen_at
                    ELSE excluded.first_seen_at
                END,
                last_seen_at = CASE
                    WHEN excluded.last_seen_at IS NULL THEN relationships.last_seen_at
                    WHEN relationships.last_seen_at IS NULL THEN excluded.last_seen_at
                    WHEN excluded.last_seen_at > relationships.last_seen_at
                        THEN excluded.last_seen_at
                    ELSE relationships.last_seen_at
                END
            """,
            (
                relationship.source_canonical_id,
                relationship.target_canonical_id,
                relationship.type.value,
                relationship.origin.value,
                _dt(relationship.first_seen_at),
                _dt(relationship.last_seen_at),
            ),
        )
        return self._identity_row_id(relationship)

    def link_evidence(self, relationship_id: int, evidence_id: str) -> None:
        """Attach an evidence item to a relationship (idempotent)."""
        self._conn.execute(
            "INSERT OR IGNORE INTO relationship_evidence (relationship_id, evidence_id) "
            "VALUES (?, ?)",
            (relationship_id, evidence_id),
        )

    def outgoing(self, canonical_id: str) -> tuple[Relationship, ...]:
        return self._for("source_canonical_id = ?", (canonical_id,))

    def incoming(self, canonical_id: str) -> tuple[Relationship, ...]:
        return self._for("target_canonical_id = ?", (canonical_id,))

    def all(self) -> tuple[Relationship, ...]:
        """Every stored relationship candidate, in deterministic identity order."""
        rows = self._conn.execute(
            "SELECT * FROM relationships "
            "ORDER BY source_canonical_id, target_canonical_id, type, origin"
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def for_scan_run(self, scan_run_id: int) -> tuple[Relationship, ...]:
        """The candidates a scan run actually (re)observed, in identity order.

        The read behind snapshot-scoped reconciliation. A candidate counts
        for a run when at least one of its linked evidence records was
        written by that run — evidence is what ties a candidate to the scan
        that observed it, so a candidate nobody re-observed stays out of that
        run's analysis and historic evidence cannot silently shape a newer
        scan's findings.
        """
        rows = self._conn.execute(
            "SELECT DISTINCT relationships.* FROM relationships "
            "JOIN relationship_evidence ON relationship_evidence.relationship_id "
            "= relationships.id "
            "JOIN evidence ON evidence.id = relationship_evidence.evidence_id "
            "WHERE evidence.scan_run_id = ? "
            "ORDER BY relationships.source_canonical_id, relationships.target_canonical_id, "
            "relationships.type, relationships.origin",
            (scan_run_id,),
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def _for(self, where: str, params: tuple[str, ...]) -> tuple[Relationship, ...]:
        rows = self._conn.execute(f"SELECT * FROM relationships WHERE {where}", params).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def _identity_row_id(self, relationship: Relationship) -> int:
        row = self._conn.execute(
            "SELECT id FROM relationships WHERE source_canonical_id = ? "
            "AND target_canonical_id = ? AND type = ? AND origin = ?",
            (
                relationship.source_canonical_id,
                relationship.target_canonical_id,
                relationship.type.value,
                relationship.origin.value,
            ),
        ).fetchone()
        return int(row["id"])

    def _hydrate(self, row: sqlite3.Row) -> Relationship:
        evidence_rows = self._conn.execute(
            "SELECT evidence_id FROM relationship_evidence WHERE relationship_id = ?",
            (row["id"],),
        ).fetchall()
        return Relationship(
            source_canonical_id=row["source_canonical_id"],
            target_canonical_id=row["target_canonical_id"],
            type=RelationshipType(row["type"]),
            origin=RelationshipOrigin(row["origin"]),
            first_seen_at=_parse_dt(row["first_seen_at"]),
            last_seen_at=_parse_dt(row["last_seen_at"]),
            evidence_ids=tuple(er["evidence_id"] for er in evidence_rows),
        )


# --- coverage ---------------------------------------------------------------


class CoverageRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def add(self, coverage: Coverage, scan_run_id: int | None = None) -> None:
        """Append a coverage record. Coverage is scan-level history."""
        self._conn.execute(
            "INSERT INTO coverage (source, status, reason, region, recorded_at, scan_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                coverage.source.value,
                coverage.status.value,
                coverage.reason,
                coverage.region,
                coverage.recorded_at.isoformat(),
                scan_run_id,
            ),
        )

    def all_records(self) -> tuple[Coverage, ...]:
        rows = self._conn.execute("SELECT * FROM coverage ORDER BY recorded_at, id").fetchall()
        return tuple(
            Coverage(
                source=EvidenceSource(row["source"]),
                status=CoverageStatus(row["status"]),
                reason=row["reason"],
                region=row["region"],
                recorded_at=datetime.fromisoformat(row["recorded_at"]),
            )
            for row in rows
        )

    def for_scan_run(self, scan_run_id: int) -> tuple[Coverage, ...]:
        """The coverage records one scan run recorded, in (recorded_at, id) order.

        Snapshot-scoped reconciliation reads this so that the coverage gating
        a pass applies is the coverage of the very scan whose candidates it
        is classifying — never a mix of one run's candidates and another
        run's coverage.
        """
        rows = self._conn.execute(
            "SELECT * FROM coverage WHERE scan_run_id = ? ORDER BY recorded_at, id",
            (scan_run_id,),
        ).fetchall()
        return tuple(
            Coverage(
                source=EvidenceSource(row["source"]),
                status=CoverageStatus(row["status"]),
                reason=row["reason"],
                region=row["region"],
                recorded_at=datetime.fromisoformat(row["recorded_at"]),
            )
            for row in rows
        )


# --- terraform addresses ----------------------------------------------------


class TerraformAddressRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, change: TerraformChange, scan_run_id: int | None = None) -> None:
        self._conn.execute(
            """
            INSERT INTO terraform_addresses (
                address, tf_resource_type, actions_json, canonical_id, scan_run_id
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (address) DO UPDATE SET
                tf_resource_type = excluded.tf_resource_type,
                actions_json     = excluded.actions_json,
                canonical_id     = COALESCE(
                    excluded.canonical_id, terraform_addresses.canonical_id
                ),
                scan_run_id      = excluded.scan_run_id
            """,
            (
                change.address,
                change.tf_resource_type,
                _dump_json_list([a.value for a in change.actions]),
                change.canonical_id,
                scan_run_id,
            ),
        )

    def for_scan_run(self, scan_run_id: int) -> tuple[TerraformChange, ...]:
        """Terraform address records written by a specific scan run."""
        rows = self._conn.execute(
            "SELECT * FROM terraform_addresses WHERE scan_run_id = ? ORDER BY address",
            (scan_run_id,),
        ).fetchall()
        return tuple(
            TerraformChange(
                address=row["address"],
                tf_resource_type=row["tf_resource_type"],
                actions=tuple(ChangeAction(a) for a in _load_json_list(row["actions_json"])),
                canonical_id=row["canonical_id"],
            )
            for row in rows
        )

    def get(self, address: str) -> TerraformChange | None:
        row = self._conn.execute(
            "SELECT * FROM terraform_addresses WHERE address = ?", (address,)
        ).fetchone()
        if row is None:
            return None
        return TerraformChange(
            address=row["address"],
            tf_resource_type=row["tf_resource_type"],
            actions=tuple(ChangeAction(a) for a in _load_json_list(row["actions_json"])),
            canonical_id=row["canonical_id"],
        )


# --- identity mappings -------------------------------------------------------


class IdentityMappingRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, mapping: IdentityMapping, scan_run_id: int | None = None) -> None:
        """Insert or refresh a mapping keyed by its identity pair.

        The key is (terraform canonical ID, aws canonical ID): both source
        identities are preserved, and re-computing the same join in a later
        scan rewrites the same row (refreshing its anchor run) rather than
        accumulating history.
        """
        self._conn.execute(
            """
            INSERT INTO identity_mappings (
                terraform_canonical_id, aws_canonical_id, basis, matched_value,
                evidence_id, reason, scan_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (terraform_canonical_id, aws_canonical_id) DO UPDATE SET
                basis         = excluded.basis,
                matched_value = excluded.matched_value,
                evidence_id   = excluded.evidence_id,
                reason        = excluded.reason,
                scan_run_id   = excluded.scan_run_id
            """,
            (
                mapping.terraform_canonical_id,
                mapping.aws_canonical_id,
                mapping.basis.value,
                mapping.matched_value,
                mapping.evidence_id,
                mapping.reason,
                scan_run_id,
            ),
        )

    def for_scan_run(self, scan_run_id: int) -> tuple[IdentityMapping, ...]:
        """The mappings a scan run computed, in deterministic identity order.

        Mappings only exist for scans that observed both worlds, so anchoring
        to the run keeps a reconciliation pass from translating through a
        join that its own scan context never established.
        """
        rows = self._conn.execute(
            "SELECT * FROM identity_mappings WHERE scan_run_id = ? "
            "ORDER BY terraform_canonical_id, aws_canonical_id",
            (scan_run_id,),
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM identity_mappings").fetchone()[0])

    @staticmethod
    def _hydrate(row: sqlite3.Row) -> IdentityMapping:
        return IdentityMapping(
            terraform_canonical_id=row["terraform_canonical_id"],
            aws_canonical_id=row["aws_canonical_id"],
            basis=MappingBasis(row["basis"]),
            matched_value=row["matched_value"],
            evidence_id=row["evidence_id"],
            reason=row["reason"],
        )


# --- findings ---------------------------------------------------------------


class FindingRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(self, finding: Finding, scan_run_id: int | None = None) -> None:
        self._conn.execute(
            """
            INSERT INTO findings (
                id, subject_canonical_id, conclusion, explanation,
                evidence_ids_json, unavailable_sources_json, scan_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET
                subject_canonical_id       = excluded.subject_canonical_id,
                conclusion                 = excluded.conclusion,
                explanation                = excluded.explanation,
                evidence_ids_json          = excluded.evidence_ids_json,
                unavailable_sources_json   = excluded.unavailable_sources_json,
                scan_run_id                = excluded.scan_run_id
            """,
            (
                finding.id,
                finding.subject_canonical_id,
                finding.conclusion.value,
                finding.explanation,
                _dump_json_list(finding.evidence_ids),
                _dump_json_list([s.value for s in finding.unavailable_sources]),
                scan_run_id,
            ),
        )

    def get(self, finding_id: str) -> Finding | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._hydrate(row) if row is not None else None

    def for_scan_run(self, scan_run_id: int) -> tuple[Finding, ...]:
        """Findings written by a specific scan run."""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_run_id = ? ORDER BY id", (scan_run_id,)
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def for_subject(self, canonical_id: str) -> tuple[Finding, ...]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE subject_canonical_id = ?", (canonical_id,)
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def delete_except(self, keep: set[str]) -> int:
        """Delete every finding whose ID is not in ``keep``; return how many.

        Findings are the reconciliation pass's own output, and each pass
        reflects exactly one scan snapshot — a finding the current pass did
        not regenerate is stale for that snapshot and must not survive to
        influence later reads. Candidates and evidence are never touched.
        """
        rows = self._conn.execute("SELECT id FROM findings").fetchall()
        stale = [row["id"] for row in rows if row["id"] not in keep]
        for finding_id in stale:
            self._conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        return len(stale)

    @staticmethod
    def _hydrate(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            subject_canonical_id=row["subject_canonical_id"],
            conclusion=Conclusion(row["conclusion"]),
            explanation=row["explanation"],
            evidence_ids=_load_json_list(row["evidence_ids_json"]),
            unavailable_sources=tuple(
                EvidenceSource(s) for s in _load_json_list(row["unavailable_sources_json"])
            ),
        )


# --- store facade -----------------------------------------------------------


class ScanSession:
    """Repositories bound to one scan run, inside its transaction."""

    def __init__(self, store: ScanStore, scan_run_id: int) -> None:
        self.scan_run_id = scan_run_id
        self._store = store

    def upsert_resource(self, resource: Resource) -> None:
        self._store.resources.upsert(resource, scan_run_id=self.scan_run_id)

    def upsert_evidence(
        self, evidence: Evidence, raw_payload: dict[str, Any] | None = None
    ) -> None:
        self._store.evidence.upsert(evidence, raw_payload, scan_run_id=self.scan_run_id)

    def upsert_relationship(
        self, relationship: Relationship, evidence_ids: Sequence[str] = ()
    ) -> int:
        relationship_id = self._store.relationships.upsert(relationship)
        for evidence_id in evidence_ids:
            self._store.relationships.link_evidence(relationship_id, evidence_id)
        return relationship_id

    def add_coverage(self, coverage: Coverage) -> None:
        self._store.coverage.add(coverage, scan_run_id=self.scan_run_id)

    def upsert_terraform_address(self, change: TerraformChange) -> None:
        self._store.terraform_addresses.upsert(change, scan_run_id=self.scan_run_id)

    def add_identity_mapping(self, mapping: IdentityMapping) -> None:
        self._store.identity_mappings.upsert(mapping, scan_run_id=self.scan_run_id)

    def upsert_finding(self, finding: Finding) -> None:
        self._store.findings.upsert(finding, scan_run_id=self.scan_run_id)

    def delete_stale_findings(self, keep: set[str]) -> int:
        """Remove findings absent from ``keep`` — a reconciliation pass's way
        of ensuring conclusions that no longer hold cannot survive it."""
        return self._store.findings.delete_except(keep)


class ScanStore:
    """All repositories over one connection, plus the scan transaction boundary."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.scan_runs = ScanRunRepository(conn)
        self.resources = ResourceRepository(conn)
        self.evidence = EvidenceRepository(conn)
        self.relationships = RelationshipRepository(conn)
        self.coverage = CoverageRepository(conn)
        self.terraform_addresses = TerraformAddressRepository(conn)
        self.identity_mappings = IdentityMappingRepository(conn)
        self.findings = FindingRepository(conn)

    @contextmanager
    def scan(
        self,
        *,
        source: EvidenceSource,
        region: str | None = None,
        account: str | None = None,
    ) -> Iterator[ScanSession]:
        """Run one scan as one transaction: commit on success, roll back on any error."""
        with transaction(self.conn):
            run_id = self.scan_runs.create(source=source, region=region, account=account)
            yield ScanSession(self, run_id)
            self.scan_runs.finish(run_id)

    def get_resource_context(
        self, canonical_id: str, *, resolver: IdentityResolver | None = None
    ) -> ResourceContext | None:
        """Resource plus its relationships, linked evidence, and coverage.

        The read behind ``reality why`` and ``reality impact``: one call
        returns the resource, outgoing and incoming relationships (each with
        its evidence IDs), the evidence items linked to those relationships
        or referencing the resource directly, and all coverage records.
        Returns ``None`` when the resource has never been stored.

        When ``resolver`` is given, the subject is resolved through compatible
        identities first, so a less-qualified reference (an accountless S3
        bucket ARN) reaches the stored, account-qualified resource and the
        edges that point at it.
        """
        if resolver is not None:
            resolved = _resolve_stored(resolver, canonical_id)
            if resolved is None:
                return None
            canonical_id = resolved
            resource = self.resources.get(canonical_id)
            outgoing = resolver.outgoing(canonical_id)
            incoming = resolver.incoming(canonical_id)
        else:
            resource = self.resources.get(canonical_id)
            outgoing = self.relationships.outgoing(canonical_id)
            incoming = self.relationships.incoming(canonical_id)
        if resource is None:
            return None
        linked: list[str] = []
        for relationship in (*outgoing, *incoming):
            linked.extend(relationship.evidence_ids)
        direct = self.evidence.ids_referencing(canonical_id)
        evidence_ids: dict[str, None] = {}  # insertion-ordered dedup
        for evidence_id in (*linked, *direct):
            evidence_ids.setdefault(evidence_id, None)
        records = tuple(
            record
            for evidence_id in evidence_ids
            if (record := self.evidence.get_record(evidence_id)) is not None
        )
        return ResourceContext(
            resource=resource,
            outgoing=outgoing,
            incoming=incoming,
            evidence=records,
            coverage=self.coverage.all_records(),
        )
