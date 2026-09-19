"""Unit tests for hidden-dependency detection.

The tests drive :class:`HiddenDependencyService` both directly with
hand-built reconciliation output and end-to-end through a real
:class:`ReconcileService` run over a seeded store. The gates under test:
only UNDOCUMENTED findings qualify, both endpoints must be resolved
identities, and at least one *observed* evidence record must back the
claim — plus the qualitative confidence band and its text rationale.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reality.domain.enums import (
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
)
from reality.domain.models import Coverage, Evidence, Relationship
from reality.services.hidden_dependencies import (
    ConfidenceBand,
    HiddenDependencyService,
)
from reality.services.reconcile import ReconcileService, finding_id
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanSession, ScanStore
from reality.storage.sqlite import connect

WEB = "aws/ec2/instance/eu-west-1/123456789012/i-0web"
OTHER_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0zzz999"
PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
DATA_LAKE = "aws/s3/bucket/-/-/data-lake"
UNRESOLVED_WILDCARD = "unresolved/-/-/-/-/arn:aws:s3:::data-lake/*"

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
}


@pytest.fixture()
def store(tmp_path: Path) -> ScanStore:
    conn = connect(tmp_path / "hidden.db")
    migrate(conn)
    yield ScanStore(conn)
    conn.close()


def add_evidence(
    store: ScanStore,
    *,
    evidence_id: str,
    source: EvidenceSource,
    strength: EvidenceStrength,
) -> None:
    evidence_type = {
        EvidenceSource.CLOUDTRAIL: EvidenceType.API_EVENT,
        EvidenceSource.AWS_RESOURCES: EvidenceType.OBSERVED_ATTRIBUTE,
        EvidenceSource.TERRAFORM_STATE: EvidenceType.CONFIG_REFERENCE,
    }.get(source, EvidenceType.POLICY_STATEMENT)
    with store.scan(source=source) as session:
        session.upsert_evidence(
            Evidence(
                id=evidence_id,
                source=source,
                type=evidence_type,
                actor="test",
                source_ref=WEB,
                target_ref=OTHER_SG,
                source_canonical_id=WEB,
                target_canonical_id=OTHER_SG,
                strength=strength,
                raw_locator=f"test#{evidence_id}",
                explanation="seeded evidence",
            )
        )


def add_observed_candidate(
    session: ScanSession,
    *,
    source: str = WEB,
    target: str = OTHER_SG,
    rel_type: RelationshipType = RelationshipType.ATTACHED_TO,
    origin: RelationshipOrigin = RelationshipOrigin.CLOUDTRAIL,
    evidence_id: str,
    strength: EvidenceStrength = EvidenceStrength.HIGH,
) -> None:
    """Seed one candidate plus its backing evidence, the way a scan would.

    Takes the session of a single scan run: reconciliation analyses one
    snapshot, so everything these end-to-end tests seed must share a run.
    """
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


def add_coverage(session: ScanSession, source: EvidenceSource, status: CoverageStatus) -> None:
    session.add_coverage(Coverage(source=source, status=status, reason="seeded coverage"))


def undocumented(
    *,
    source: str = WEB,
    target: str = OTHER_SG,
    rel_type: RelationshipType = RelationshipType.ATTACHED_TO,
    evidence_ids: tuple[str, ...] = ("ct:1",),
    conclusion: Conclusion = Conclusion.UNDOCUMENTED,
):
    """A reconciliation output item, built the way ReconcileService would."""
    from reality.services.reconcile import ReconciledRelationship

    return ReconciledRelationship(
        finding_id=finding_id(source, target, rel_type),
        source_canonical_id=source,
        target_canonical_id=target,
        relationship_type=rel_type,
        conclusion=conclusion,
        explanation="observed with no matching Terraform declaration",
        evidence_ids=evidence_ids,
    )


# --- positive cases --------------------------------------------------------------


def test_observed_undeclared_relationship_is_a_hidden_dependency(store: ScanStore) -> None:
    add_evidence(
        store, evidence_id="ct:1", source=EvidenceSource.CLOUDTRAIL, strength=EvidenceStrength.HIGH
    )
    reported = HiddenDependencyService(store).detect((undocumented(),))

    assert len(reported) == 1
    item = reported[0]
    assert item.finding_id == finding_id(WEB, OTHER_SG, RelationshipType.ATTACHED_TO)
    assert item.source_canonical_id == WEB
    assert item.target_canonical_id == OTHER_SG
    assert item.band is ConfidenceBand.STRONG
    assert item.evidence_ids == ("ct:1",)
    assert "cloudtrail" in item.rationale
    assert "no Terraform declaration" in item.rationale
    assert "missing rather than unread" in item.rationale


def test_medium_evidence_gives_moderate_band(store: ScanStore) -> None:
    add_evidence(
        store,
        evidence_id="aws:1",
        source=EvidenceSource.AWS_RESOURCES,
        strength=EvidenceStrength.MEDIUM,
    )
    reported = HiddenDependencyService(store).detect((undocumented(evidence_ids=("aws:1",)),))
    assert reported[0].band is ConfidenceBand.MODERATE


def test_low_evidence_gives_weak_band_with_caveat(store: ScanStore) -> None:
    add_evidence(
        store,
        evidence_id="ct:1",
        source=EvidenceSource.CLOUDTRAIL,
        strength=EvidenceStrength.LOW,
    )
    reported = HiddenDependencyService(store).detect((undocumented(),))

    item = reported[0]
    assert item.band is ConfidenceBand.WEAK
    assert "lead to verify, not a conclusion" in item.rationale


def test_strongest_evidence_sets_the_band(store: ScanStore) -> None:
    add_evidence(
        store,
        evidence_id="ct:low",
        source=EvidenceSource.CLOUDTRAIL,
        strength=EvidenceStrength.LOW,
    )
    add_evidence(
        store,
        evidence_id="aws:high",
        source=EvidenceSource.AWS_RESOURCES,
        strength=EvidenceStrength.HIGH,
    )
    reported = HiddenDependencyService(store).detect(
        (undocumented(evidence_ids=("ct:low", "aws:high")),)
    )
    assert reported[0].band is ConfidenceBand.STRONG
    assert reported[0].evidence_ids == ("ct:low", "aws:high")


def test_rationale_carries_no_fabricated_numbers(store: ScanStore) -> None:
    add_evidence(
        store, evidence_id="ct:1", source=EvidenceSource.CLOUDTRAIL, strength=EvidenceStrength.HIGH
    )
    reported = HiddenDependencyService(store).detect((undocumented(),))
    assert re.search(r"\d+\.\d+", reported[0].rationale) is None


# --- negative cases: the narrow gates ---------------------------------------------


def test_unresolved_endpoints_are_excluded(store: ScanStore) -> None:
    add_evidence(
        store, evidence_id="ct:1", source=EvidenceSource.CLOUDTRAIL, strength=EvidenceStrength.HIGH
    )
    service = HiddenDependencyService(store)
    assert service.detect((undocumented(target=UNRESOLVED_WILDCARD),)) == ()
    assert service.detect((undocumented(source=UNRESOLVED_WILDCARD, target=WEB),)) == ()


def test_permission_evidence_alone_never_qualifies(store: ScanStore) -> None:
    add_evidence(
        store,
        evidence_id="iam:1",
        source=EvidenceSource.IAM,
        strength=EvidenceStrength.HIGH,
    )
    reported = HiddenDependencyService(store).detect(
        (undocumented(evidence_ids=("iam:1",), rel_type=RelationshipType.PERMISSION_ON),)
    )
    assert reported == ()


def test_missing_evidence_rows_are_skipped(store: ScanStore) -> None:
    # A dangling evidence id must not crash the projection; with no observed
    # record left, the item simply does not qualify.
    add_evidence(
        store,
        evidence_id="aws:1",
        source=EvidenceSource.AWS_RESOURCES,
        strength=EvidenceStrength.HIGH,
    )
    reported = HiddenDependencyService(store).detect(
        (undocumented(evidence_ids=("aws:1", "no-such-evidence")),)
    )
    assert len(reported) == 1
    assert reported[0].evidence_ids == ("aws:1",)


def test_iam_evidence_does_not_count_but_cloudtrail_does(store: ScanStore) -> None:
    add_evidence(
        store,
        evidence_id="iam:1",
        source=EvidenceSource.IAM,
        strength=EvidenceStrength.HIGH,
    )
    add_evidence(
        store,
        evidence_id="ct:1",
        source=EvidenceSource.CLOUDTRAIL,
        strength=EvidenceStrength.MEDIUM,
    )
    reported = HiddenDependencyService(store).detect(
        (undocumented(evidence_ids=("iam:1", "ct:1")),)
    )
    assert len(reported) == 1
    assert reported[0].evidence_ids == ("ct:1",)  # only the observed record backs it
    assert reported[0].band is ConfidenceBand.MODERATE


@pytest.mark.parametrize(
    "conclusion",
    [
        Conclusion.CONFIRMED,
        Conclusion.POSSIBLE,
        Conclusion.DECLARED_ONLY,
        Conclusion.UNKNOWN,
    ],
)
def test_only_undocumented_conclusions_project(store: ScanStore, conclusion: Conclusion) -> None:
    add_evidence(
        store, evidence_id="ct:1", source=EvidenceSource.CLOUDTRAIL, strength=EvidenceStrength.HIGH
    )
    reported = HiddenDependencyService(store).detect((undocumented(conclusion=conclusion),))
    assert reported == ()


# --- end to end: projection of a real reconcile run --------------------------------


def test_projection_of_a_real_reconcile_run(store: ScanStore) -> None:
    # An observed dependency nobody declared: the processor role writing to
    # the data lake, seen only in CloudTrail — all in the one scan run the
    # pass will analyse.
    with store.scan(source=EvidenceSource.CLOUDTRAIL) as session:
        add_observed_candidate(
            session,
            source=PROCESSOR_ROLE,
            target=DATA_LAKE,
            rel_type=RelationshipType.PERMISSION_ON,
            origin=RelationshipOrigin.CLOUDTRAIL,
            evidence_id="ct:put",
            strength=EvidenceStrength.HIGH,
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.CLOUDTRAIL, CoverageStatus.AVAILABLE)

    report = ReconcileService(store).run()
    undocumented_items = [
        item for item in report.findings if item.conclusion == Conclusion.UNDOCUMENTED
    ]
    assert len(undocumented_items) == 1

    reported = HiddenDependencyService(store).detect(report.findings)
    assert len(reported) == 1
    item = reported[0]
    assert item.finding_id == finding_id(PROCESSOR_ROLE, DATA_LAKE, RelationshipType.PERMISSION_ON)
    assert item.band is ConfidenceBand.STRONG
    assert item.evidence_ids == ("ct:put",)


def test_end_to_end_declared_observed_pair_is_not_hidden(store: ScanStore) -> None:
    # Same triple declared and observed reconciles to CONFIRMED and must not
    # surface as a hidden dependency.
    with store.scan(source=EvidenceSource.AWS_RESOURCES) as session:
        add_observed_candidate(session, evidence_id="aws:1", origin=RelationshipOrigin.AWS_OBSERVED)
        add_observed_candidate(
            session, evidence_id="tf:1", origin=RelationshipOrigin.TERRAFORM_DECLARED
        )
        add_coverage(session, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
        add_coverage(session, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)

    report = ReconcileService(store).run()
    assert report.findings[0].conclusion == Conclusion.CONFIRMED
    assert HiddenDependencyService(store).detect(report.findings) == ()
