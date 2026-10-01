"""Unit tests for deterministic reconciliation over one scan snapshot.

Every test seeds a temporary store directly with relationship candidates,
evidence, coverage records, and — for the cross-namespace tests — identity
mappings, all inside one scan run (the snapshot the pass will analyse): no
adapters, no AWS, no network. The central properties under test: matching
happens only on exact canonical (source, target, type) triples, an
evidence-backed identity mapping is the one thing that can join the
Terraform and AWS namespaces, evidence anchored to a different scan run
cannot influence the pass, missing coverage turns conclusions into UNKNOWN
instead of guesses, and DECLARED_ONLY never implies inactivity.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from reality.domain.enums import (
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    MappingBasis,
    RelationshipOrigin,
    RelationshipType,
)
from reality.domain.models import Coverage, Evidence, IdentityMapping, Relationship
from reality.services.reconcile import ReconcileService, finding_id
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanSession, ScanStore
from reality.storage.sqlite import connect

WEB = "aws/ec2/instance/eu-west-1/123456789012/i-0web"
WEB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0aaa111"
OTHER_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0zzz999"
PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
DATA_LAKE = "aws/s3/bucket/-/-/data-lake"
UNRESOLVED_WILDCARD = "unresolved/-/-/-/-/arn:aws:s3:::data-lake/*"

#: The same two resources as WEB / WEB_SG, in the Terraform namespace.
TF_WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"
TF_WEB_SG = "terraform/aws/aws_security_group/-/-/aws_security_group.web_sg"

#: What evidence a candidate of each origin is seeded with.
ORIGIN_EVIDENCE: dict[RelationshipOrigin, tuple[EvidenceSource, EvidenceType]] = {
    RelationshipOrigin.TERRAFORM_DECLARED: (
        EvidenceSource.TERRAFORM_STATE,
        EvidenceType.CONFIG_REFERENCE,
    ),
    RelationshipOrigin.AWS_OBSERVED: (
        EvidenceSource.AWS_RESOURCES,
        EvidenceType.OBSERVED_ATTRIBUTE,
    ),
    RelationshipOrigin.CLOUDTRAIL: (EvidenceSource.CLOUDTRAIL, EvidenceType.API_EVENT),
    RelationshipOrigin.IAM_POLICY: (EvidenceSource.IAM, EvidenceType.POLICY_STATEMENT),
    RelationshipOrigin.SIMULATION: (EvidenceSource.SIMULATION, EvidenceType.OBSERVED_ATTRIBUTE),
}


@pytest.fixture()
def store(tmp_path: Path) -> ScanStore:
    conn = connect(tmp_path / "reconcile.db")
    migrate(conn)
    yield ScanStore(conn)
    conn.close()


@contextmanager
def seed_run(
    store: ScanStore, source: EvidenceSource = EvidenceSource.TERRAFORM_STATE
) -> Iterator[ScanSession]:
    """Open one scan run and yield its session for seeding.

    Everything a test seeds goes into this single run — the snapshot the
    reconciliation pass will analyse — because evidence split across runs is
    exactly what the snapshot boundary must exclude.
    """
    with store.scan(source=source) as session:
        yield session


def add_candidate(
    session: ScanSession,
    *,
    source: str,
    target: str,
    rel_type: RelationshipType,
    origin: RelationshipOrigin,
    evidence_id: str,
    strength: EvidenceStrength = EvidenceStrength.HIGH,
) -> None:
    """Seed one relationship candidate with one backing evidence record."""
    evidence_source, evidence_type = ORIGIN_EVIDENCE[origin]
    session.upsert_evidence(
        Evidence(
            id=evidence_id,
            source=evidence_source,
            type=evidence_type,
            actor="test",
            source_ref=source,
            target_ref=target,
            source_canonical_id=source,
            target_canonical_id=target,
            strength=strength,
            raw_locator=f"test#{evidence_id}",
            explanation="seeded candidate evidence",
        )
    )
    session.upsert_relationship(
        Relationship(
            source_canonical_id=source,
            target_canonical_id=target,
            type=rel_type,
            origin=origin,
            evidence_ids=(evidence_id,),
        ),
        (evidence_id,),
    )


def add_mapping(session: ScanSession, *, terraform: str, aws: str, evidence_id: str) -> None:
    """Seed one identity mapping plus the evidence record backing it."""
    session.upsert_evidence(
        Evidence(
            id=evidence_id,
            source=EvidenceSource.TERRAFORM_STATE,
            type=EvidenceType.IDENTITY_MATCH,
            actor="terraform",
            source_ref=terraform,
            target_ref=aws,
            source_canonical_id=terraform,
            target_canonical_id=aws,
            strength=EvidenceStrength.HIGH,
            raw_locator=f"test#{evidence_id}",
            explanation="seeded identity mapping",
        )
    )
    session.add_identity_mapping(
        IdentityMapping(
            terraform_canonical_id=terraform,
            aws_canonical_id=aws,
            basis=MappingBasis.ARN,
            matched_value="arn:aws:fake:eu-west-1:123456789012:thing/x",
            evidence_id=evidence_id,
            reason="seeded identity mapping",
        )
    )


def add_coverage(session: ScanSession, source: EvidenceSource, status: CoverageStatus) -> None:
    session.add_coverage(Coverage(source=source, status=status, reason="seeded coverage"))


def conclusions(report: object) -> dict[str, Conclusion]:
    return {item.finding_id: item.conclusion for item in report.findings}  # type: ignore[attr-defined]


def full_coverage(session: ScanSession) -> None:
    add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)


# --- the five conclusions -------------------------------------------------------


def test_declared_and_observed_on_one_triple_is_confirmed(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        full_coverage(session)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.CONFIRMED
    # Evidence order follows the deterministic identity order of candidates
    # (aws_observed sorts before terraform_declared), not insertion order.
    assert item.evidence_ids == ("aws:1", "tf:1")
    assert item.unavailable_sources == ()
    assert "both worlds agree" in item.explanation
    assert report.counts[Conclusion.CONFIRMED.value] == 1


def test_observed_without_declaration_is_undocumented(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.UNDOCUMENTED
    assert "missing rather than unread" in item.explanation
    # The finding is persisted, separate from the untouched candidates.
    persisted = store.findings.get(item.finding_id)
    assert persisted is not None
    assert persisted.conclusion == Conclusion.UNDOCUMENTED
    assert persisted.evidence_ids == ("aws:1",)


def test_iam_permission_without_usage_is_possible(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=PROCESSOR_ROLE,
            target=DATA_LAKE,
            rel_type=RelationshipType.PERMISSION_ON,
            origin=RelationshipOrigin.IAM_POLICY,
            evidence_id="iam:1",
        )
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.POSSIBLE
    assert "possibility, not a confirmed dependency" in item.explanation


def test_declared_without_observation_is_declared_only_not_inactive(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.DECLARED_ONLY
    assert "not evidence that the dependency is inactive" in item.explanation


def test_declared_only_with_unresolved_target_is_reported(store: ScanStore) -> None:
    # An unresolved declared reference still gets a finding; matching it with
    # anything is impossible by construction, so it is DECLARED_ONLY.
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=UNRESOLVED_WILDCARD,
            rel_type=RelationshipType.REFERENCES,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()
    assert report.findings[0].conclusion == Conclusion.DECLARED_ONLY


# --- coverage gates turn conclusions into UNKNOWN ---------------------------------


def test_unavailable_terraform_blocks_undocumented(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.UNKNOWN  # maybe it IS declared; we never looked
    assert set(item.unavailable_sources) == {
        EvidenceSource.TERRAFORM_STATE,
        EvidenceSource.TERRAFORM_PLAN,
    }
    assert "could not be determined" in item.explanation


def test_not_requested_terraform_also_blocks_undocumented(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.NOT_REQUESTED)
    report = ReconcileService(store).run()
    assert report.findings[0].conclusion == Conclusion.UNKNOWN


def test_unavailable_observation_blocks_declared_only(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
    report = ReconcileService(store).run()  # no observed coverage in the run at all

    item = report.findings[0]
    assert item.conclusion == Conclusion.UNKNOWN
    assert set(item.unavailable_sources) == {
        EvidenceSource.AWS_RESOURCES,
        EvidenceSource.CLOUDTRAIL,
    }


def test_unavailable_cloudtrail_does_not_downgrade_permission_only(store: ScanStore) -> None:
    """A granted permission is POSSIBLE even when CloudTrail is unavailable.

    Data-plane usage is never visible to a management-event scan, so CloudTrail
    coverage cannot decide this question in either direction. An UNAVAILABLE
    management source is a gap in what was *observed*, not evidence that a
    permission went unused, so it must not downgrade POSSIBLE to UNKNOWN.
    """
    with seed_run(store) as session:
        add_candidate(
            session,
            source=PROCESSOR_ROLE,
            target=DATA_LAKE,
            rel_type=RelationshipType.PERMISSION_ON,
            origin=RelationshipOrigin.IAM_POLICY,
            evidence_id="iam:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.CLOUDTRAIL, CoverageStatus.UNAVAILABLE)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.POSSIBLE
    assert item.unavailable_sources == ()
    assert "data-plane usage is not visible" in item.explanation


def test_latest_coverage_record_wins(store: ScanStore) -> None:
    """Within one run, the most recent record for a source is the one that counts.

    Both observed sources go available-then-unavailable. If the *earlier* record
    won, the run would still look fully observed and the candidate would come
    out DECLARED_ONLY; because the later record wins, neither observed source is
    usable and the conclusion must be UNKNOWN.
    """
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.CLOUDTRAIL, CoverageStatus.AVAILABLE)
        # The more recent record within the same run wins.
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.UNAVAILABLE)
        add_coverage(session, EvidenceSource.CLOUDTRAIL, CoverageStatus.UNAVAILABLE)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.UNKNOWN
    assert set(item.unavailable_sources) == {
        EvidenceSource.AWS_RESOURCES,
        EvidenceSource.CLOUDTRAIL,
    }


# --- matching is exact triples only -----------------------------------------------


def test_triples_match_only_on_exact_source_target_and_type(store: ScanStore) -> None:
    # Declared (WEB -> WEB_SG, ATTACHED_TO), but observed with a different
    # target and with a different type: none of them match.
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_candidate(  # same pair, different type
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.DEPENDS_ON,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_id="ct:1",
        )
        add_candidate(  # same type, different target
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        full_coverage(session)
    report = ReconcileService(store).run()

    by_id = conclusions(report)
    assert by_id == {
        finding_id(WEB, WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.DECLARED_ONLY,
        finding_id(WEB, WEB_SG, RelationshipType.DEPENDS_ON): Conclusion.UNDOCUMENTED,
        finding_id(WEB, OTHER_SG, RelationshipType.ATTACHED_TO): Conclusion.UNDOCUMENTED,
    }


def test_duplicate_evidence_appears_once(store: ScanStore) -> None:
    # The same evidence record linked to both the declared and the observed
    # candidate of one triple.
    with seed_run(store) as session:
        for origin in (RelationshipOrigin.TERRAFORM_DECLARED, RelationshipOrigin.AWS_OBSERVED):
            add_candidate(
                session,
                source=WEB,
                target=WEB_SG,
                rel_type=RelationshipType.ATTACHED_TO,
                origin=origin,
                evidence_id="shared:1",
            )
        full_coverage(session)
    report = ReconcileService(store).run()
    assert report.findings[0].evidence_ids == ("shared:1",)


def test_multiple_observed_origins_accumulate(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=PROCESSOR_ROLE,
            target=DATA_LAKE,
            rel_type=RelationshipType.DEPENDS_ON,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_id="ct:1",
        )
        add_candidate(
            session,
            source=PROCESSOR_ROLE,
            target=DATA_LAKE,
            rel_type=RelationshipType.DEPENDS_ON,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()

    item = report.findings[0]
    assert item.conclusion == Conclusion.UNDOCUMENTED
    assert item.evidence_ids == ("aws:1", "ct:1")  # deterministic identity order
    assert "cloudtrail" in item.explanation and "aws_observed" in item.explanation


def test_simulation_only_candidates_are_ignored(store: ScanStore) -> None:
    with seed_run(store, source=EvidenceSource.SIMULATION) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.DEPENDS_ON,
            origin=RelationshipOrigin.SIMULATION,
            evidence_id="sim:1",
        )
    report = ReconcileService(store).run()
    assert report.findings == ()
    assert store.findings.get(finding_id(WEB, WEB_SG, RelationshipType.DEPENDS_ON)) is None


# --- identity mappings join the namespaces ----------------------------------------


def test_identity_mapping_joins_namespaces_into_confirmed(store: ScanStore) -> None:
    # The same real dependency, declared in the Terraform namespace and
    # observed in the AWS namespace: only the mappings let them meet, and
    # each namespace keeps its own finding.
    with seed_run(store) as session:
        add_candidate(
            session,
            source=TF_WEB,
            target=TF_WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_mapping(session, terraform=TF_WEB, aws=WEB, evidence_id="identity:web")
        add_mapping(session, terraform=TF_WEB_SG, aws=WEB_SG, evidence_id="identity:web-sg")
    report = ReconcileService(store).run()

    assert conclusions(report) == {
        finding_id(TF_WEB, TF_WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.CONFIRMED,
        finding_id(WEB, WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.CONFIRMED,
    }
    for item in report.findings:
        # The mapping evidence is part of the conclusion's basis on both sides.
        assert set(item.evidence_ids) == {"aws:1", "tf:1", "identity:web", "identity:web-sg"}
        assert "identity mapping" in item.explanation


def test_unmapped_namespaces_do_not_join(store: ScanStore) -> None:
    # The same shape as above but with no mappings: string equality never
    # joins a terraform/ identity to an aws/ one.
    with seed_run(store) as session:
        add_candidate(
            session,
            source=TF_WEB,
            target=TF_WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()

    assert conclusions(report) == {
        finding_id(TF_WEB, TF_WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.DECLARED_ONLY,
        finding_id(WEB, WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.UNDOCUMENTED,
    }


def test_mappings_without_candidates_produce_no_findings(store: ScanStore) -> None:
    # A mapping joins identities; it never invents a dependency.
    with seed_run(store) as session:
        add_mapping(session, terraform=TF_WEB, aws=WEB, evidence_id="identity:web")
    report = ReconcileService(store).run()
    assert report.findings == ()


def test_mapping_from_a_different_run_does_not_translate(store: ScanStore) -> None:
    # Mappings are anchored to their scan run like every other input: a
    # mapping recorded by an older run must not join a newer snapshot.
    with seed_run(store) as session:
        add_mapping(session, terraform=TF_WEB, aws=WEB, evidence_id="identity:web")
        add_mapping(session, terraform=TF_WEB_SG, aws=WEB_SG, evidence_id="identity:web-sg")
    with seed_run(store) as session:
        add_candidate(
            session,
            source=TF_WEB,
            target=TF_WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.TERRAFORM_DECLARED,
            evidence_id="tf:1",
        )
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()
    # Exactly the unmapped outcome: the older run's mappings did not translate.
    assert conclusions(report) == {
        finding_id(TF_WEB, TF_WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.DECLARED_ONLY,
        finding_id(WEB, WEB_SG, RelationshipType.ATTACHED_TO): Conclusion.UNDOCUMENTED,
    }


# --- the snapshot boundary ----------------------------------------------------------


def test_only_the_selected_snapshot_participates(store: ScanStore) -> None:
    # Run 1 observes a legacy dependency; run 2 does not re-observe it. The
    # pass analyses run 2 alone, so the legacy dependency cannot surface in it.
    with seed_run(store, source=EvidenceSource.CLOUDTRAIL) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_id="ct:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    with seed_run(store, source=EvidenceSource.AWS_RESOURCES) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()

    ids = {item.finding_id for item in report.findings}
    assert finding_id(WEB, WEB_SG, RelationshipType.ATTACHED_TO) in ids
    assert finding_id(WEB, OTHER_SG, RelationshipType.ATTACHED_TO) not in ids
    assert report.analysed_scan_run_id is not None
    assert report.analysed_scan_run_id != 1  # the latest discovery run, not run 1


def test_explicit_scan_run_id_selects_that_snapshot(store: ScanStore) -> None:
    with seed_run(store, source=EvidenceSource.CLOUDTRAIL) as session:
        first_run = session.scan_run_id
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_id="ct:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    with seed_run(store, source=EvidenceSource.AWS_RESOURCES) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)

    report = ReconcileService(store).run(scan_run_id=first_run)
    assert report.analysed_scan_run_id == first_run
    assert {item.finding_id for item in report.findings} == {
        finding_id(WEB, OTHER_SG, RelationshipType.ATTACHED_TO)
    }


def test_stale_findings_do_not_survive_a_newer_snapshot(store: ScanStore) -> None:
    # A conclusion drawn from run 1 must be gone once a newer snapshot no
    # longer supports it — otherwise historic evidence would keep influencing
    # current reports through the findings table.
    with seed_run(store, source=EvidenceSource.CLOUDTRAIL) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_id="ct:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    first = ReconcileService(store).run()
    legacy_id = finding_id(WEB, OTHER_SG, RelationshipType.ATTACHED_TO)
    assert legacy_id in {item.finding_id for item in first.findings}

    with seed_run(store, source=EvidenceSource.AWS_RESOURCES) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    second = ReconcileService(store).run()

    assert legacy_id not in {item.finding_id for item in second.findings}
    assert store.findings.get(legacy_id) is None  # deleted, not just unreported


def test_no_discovery_run_raises(store: ScanStore) -> None:
    with pytest.raises(ValueError, match="no discovery scan"):
        ReconcileService(store).run()


def test_unknown_scan_run_id_raises(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    with pytest.raises(ValueError, match="does not exist"):
        ReconcileService(store).run(scan_run_id=999)


def test_reconciliation_run_cannot_be_analysed(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()  # creates a reconciliation run
    with pytest.raises(ValueError, match="reconciliation pass"):
        ReconcileService(store).run(scan_run_id=report.scan_run_id)


# --- the pass itself: read-only, deterministic, idempotent ------------------------


def test_candidates_and_evidence_are_unchanged(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    runs_before = store.scan_runs.count()
    relationships_before = store.relationships.outgoing(WEB)
    evidence_before = store.evidence.count()

    report = ReconcileService(store).run()

    assert store.scan_runs.count() == runs_before + 1  # only the reconcile anchor
    assert store.relationships.outgoing(WEB) == relationships_before
    assert store.evidence.count() == evidence_before
    assert store.findings.get(report.findings[0].finding_id) is not None


def test_running_twice_is_idempotent(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=OTHER_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    service = ReconcileService(store)
    first = service.run()
    second = service.run()
    assert first.findings == second.findings
    assert first.counts == second.counts
    assert second.scan_run_id != first.scan_run_id


def test_run_with_no_candidates_produces_no_findings(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()
    assert report.findings == ()
    assert report.counts == {conclusion.value: 0 for conclusion in Conclusion}


def test_finding_ids_are_stable_and_readable(store: ScanStore) -> None:
    with seed_run(store) as session:
        add_candidate(
            session,
            source=WEB,
            target=WEB_SG,
            rel_type=RelationshipType.ATTACHED_TO,
            origin=RelationshipOrigin.AWS_OBSERVED,
            evidence_id="aws:1",
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ReconcileService(store).run()
    assert report.findings[0].finding_id == (f"reconcile:attached_to:{WEB}:{WEB_SG}")
