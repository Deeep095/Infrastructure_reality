"""Unit tests for blast-radius traversal and the why report.

Every test seeds a temporary store directly — resources, relationship
candidates, findings, and coverage — with no adapters and no network. The
properties under test: traversal is bounded, cycle-safe, and deterministic;
dependents are classified documented / undocumented / possible / unknown from
reconciliation findings; risk is the documented band (HIGH only for an
undocumented dependent, LOW only when nothing is known *and* the sources that
could have known were consulted); and the why report shows the resource,
relationships, evidence, findings, and coverage limitations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reality import cli
from reality.domain.enums import (
    Conclusion,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.models import Coverage, Evidence, Finding, Relationship, Resource
from reality.services.impact import (
    DEFAULT_DEPTH,
    DependentKind,
    ImpactService,
    RiskLevel,
)
from reality.services.reconcile import finding_id
from reality.services.reports import WhyService, render_why, stable_json
from reality.storage.migrations import migrate
from reality.storage.repositories import ScanStore
from reality.storage.sqlite import connect

WEB = "aws/ec2/instance/eu-west-1/123456789012/i-0web"
BATCH = "aws/ec2/instance/eu-west-1/123456789012/i-0batch"
WEB_SG = "aws/ec2/security-group/eu-west-1/123456789012/sg-0aaa111"
PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
DATA_LAKE = "aws/s3/bucket/-/-/data-lake"
TF_WEB = "terraform/aws/aws_instance/-/-/aws_instance.web"

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
    conn = connect(tmp_path / "impact.db")
    migrate(conn)
    yield ScanStore(conn)
    conn.close()


def add_resource(
    store: ScanStore,
    canonical_id: str,
    *,
    provider: str = "aws",
    resource_type: ResourceType = ResourceType.EC2_INSTANCE,
) -> None:
    with store.scan(source=EvidenceSource.SIMULATION) as session:
        session.upsert_resource(
            Resource(canonical_id=canonical_id, resource_type=resource_type, provider=provider)
        )


def add_candidate(
    store: ScanStore,
    *,
    source: str,
    target: str,
    rel_type: RelationshipType = RelationshipType.ATTACHED_TO,
    origin: RelationshipOrigin = RelationshipOrigin.AWS_OBSERVED,
    evidence_id: str,
) -> None:
    """Seed one relationship candidate with one backing evidence record."""
    evidence_source, evidence_type = ORIGIN_EVIDENCE[origin]
    with store.scan(source=evidence_source) as session:
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
                strength=EvidenceStrength.HIGH,
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


def add_finding(
    store: ScanStore,
    *,
    source: str,
    target: str,
    rel_type: RelationshipType,
    conclusion: Conclusion,
    unavailable: tuple[EvidenceSource, ...] = (),
) -> None:
    with store.scan(source=EvidenceSource.RECONCILIATION) as session:
        session.upsert_finding(
            Finding(
                id=finding_id(source, target, rel_type),
                subject_canonical_id=source,
                conclusion=conclusion,
                explanation=f"test finding: {conclusion.value}",
                evidence_ids=(),
                unavailable_sources=unavailable,
            )
        )


def add_coverage(store: ScanStore, source: EvidenceSource, status: CoverageStatus) -> None:
    with store.scan(source=source) as session:
        session.add_coverage(Coverage(source=source, status=status, reason="seeded coverage"))


def full_coverage(store: ScanStore) -> None:
    add_coverage(store, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.TERRAFORM_PLAN, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.IAM, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.CLOUDTRAIL, CoverageStatus.AVAILABLE)


def subject_with_dependent(store: ScanStore) -> None:
    """A security group with one observed dependent web instance."""
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(store, source=WEB, target=WEB_SG, evidence_id="aws:1")


# --- traversal ---------------------------------------------------------------------


def test_unknown_resource_has_no_blast_radius(store: ScanStore) -> None:
    assert ImpactService(store).blast_radius("aws/ec2/instance/-/-/i-0nope") is None


def test_direct_dependent_carries_path_evidence_and_provenance(store: ScanStore) -> None:
    subject_with_dependent(store)
    report = ImpactService(store).blast_radius(WEB_SG)

    assert report is not None
    assert report.subject_canonical_id == WEB_SG
    assert report.depth == DEFAULT_DEPTH
    (dependent,) = report.dependents
    assert dependent.canonical_id == WEB
    assert dependent.path == (WEB_SG, WEB)
    assert dependent.depth == 1
    assert dependent.evidence_ids == ("aws:1",)
    assert dependent.provenance == ("aws_observed",)


def test_transitive_dependent_reports_the_whole_path(store: ScanStore) -> None:
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(store, source=WEB, target=WEB_SG, evidence_id="aws:1")
    add_candidate(store, source=BATCH, target=WEB, evidence_id="aws:2")
    report = ImpactService(store).blast_radius(WEB_SG)

    by_id = {dependent.canonical_id: dependent for dependent in report.dependents}
    assert by_id[WEB].path == (WEB_SG, WEB)
    assert by_id[WEB].depth == 1
    assert by_id[BATCH].path == (WEB_SG, WEB, BATCH)
    assert by_id[BATCH].depth == 2
    assert by_id[BATCH].evidence_ids == ("aws:1", "aws:2")  # every edge on the path


def test_depth_limit_bounds_the_traversal(store: ScanStore) -> None:
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(store, source=WEB, target=WEB_SG, evidence_id="aws:1")
    add_candidate(store, source=BATCH, target=WEB, evidence_id="aws:2")
    report = ImpactService(store).blast_radius(WEB_SG, depth=1)

    assert [dependent.canonical_id for dependent in report.dependents] == [WEB]
    assert report.depth == 1


def test_cycle_terminates_and_reports_each_reachable_resource_once(store: ScanStore) -> None:
    # WEB -> WEB_SG and WEB_SG -> WEB: a two-node cycle around the subject.
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(store, source=WEB, target=WEB_SG, evidence_id="aws:1")
    add_candidate(store, source=WEB_SG, target=WEB, evidence_id="aws:2")
    report = ImpactService(store).blast_radius(WEB_SG)

    assert [dependent.canonical_id for dependent in report.dependents] == [WEB]
    assert report.dependents[0].path == (WEB_SG, WEB)


def test_self_loop_is_not_a_dependent(store: ScanStore) -> None:
    add_resource(store, WEB, resource_type=ResourceType.EC2_INSTANCE)
    add_candidate(store, source=WEB, target=WEB, evidence_id="aws:self")
    report = ImpactService(store).blast_radius(WEB)

    assert report.dependents == ()


def test_parallel_edges_from_one_dependent_are_aggregated(store: ScanStore) -> None:
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        evidence_id="aws:attached",
    )
    add_candidate(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.DEPENDS_ON,
        origin=RelationshipOrigin.CLOUDTRAIL,
        evidence_id="ct:depends",
    )
    report = ImpactService(store).blast_radius(WEB_SG)

    (dependent,) = report.dependents
    assert dependent.canonical_id == WEB
    assert set(dependent.evidence_ids) == {"aws:attached", "ct:depends"}
    assert dependent.provenance == ("aws_observed", "cloudtrail")


# --- dependent classification from findings -----------------------------------------


@pytest.mark.parametrize(
    ("conclusion", "kind"),
    [
        (Conclusion.CONFIRMED, DependentKind.DOCUMENTED),
        (Conclusion.DECLARED_ONLY, DependentKind.DOCUMENTED),
        (Conclusion.POSSIBLE, DependentKind.POSSIBLE),
    ],
)
def test_declared_and_permission_dependents_are_not_undocumented(
    store: ScanStore, conclusion: Conclusion, kind: DependentKind
) -> None:
    subject_with_dependent(store)
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=conclusion,
    )
    report = ImpactService(store).blast_radius(WEB_SG)

    assert report.dependents[0].kind is kind
    assert report.dependents[0].conclusion is conclusion
    assert report.risk is RiskLevel.MEDIUM


def test_undocumented_dependent_makes_the_risk_high(store: ScanStore) -> None:
    subject_with_dependent(store)
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=Conclusion.UNDOCUMENTED,
    )
    report = ImpactService(store).blast_radius(WEB_SG)

    dependent = report.dependents[0]
    assert dependent.kind is DependentKind.UNDOCUMENTED
    assert dependent.conclusion is Conclusion.UNDOCUMENTED
    assert report.risk is RiskLevel.HIGH


def test_unreconciled_edge_is_unknown_with_a_reconcile_hint(store: ScanStore) -> None:
    subject_with_dependent(store)
    report = ImpactService(store).blast_radius(WEB_SG)

    dependent = report.dependents[0]
    assert dependent.kind is DependentKind.UNKNOWN
    assert dependent.conclusion is None
    assert report.risk is RiskLevel.MEDIUM
    assert any("run reality reconcile" in note for note in report.notes)


def test_blocked_finding_is_unknown_with_the_blocking_sources(store: ScanStore) -> None:
    subject_with_dependent(store)
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=Conclusion.UNKNOWN,
        unavailable=(EvidenceSource.AWS_RESOURCES, EvidenceSource.CLOUDTRAIL),
    )
    report = ImpactService(store).blast_radius(WEB_SG)

    assert report.dependents[0].kind is DependentKind.UNKNOWN
    assert any("blocked by coverage (aws_resources, cloudtrail)" in note for note in report.notes)


def test_most_cautionary_kind_wins_across_parallel_edges(store: ScanStore) -> None:
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        evidence_id="aws:attached",
    )
    add_candidate(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.DEPENDS_ON,
        origin=RelationshipOrigin.TERRAFORM_DECLARED,
        evidence_id="tf:depends",
    )
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=Conclusion.UNDOCUMENTED,
    )
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.DEPENDS_ON,
        conclusion=Conclusion.CONFIRMED,
    )
    report = ImpactService(store).blast_radius(WEB_SG)

    (dependent,) = report.dependents
    assert dependent.kind is DependentKind.UNDOCUMENTED  # worst case, not average
    assert report.risk is RiskLevel.HIGH


# --- risk and coverage ---------------------------------------------------------------


def test_no_dependents_with_full_coverage_is_low(store: ScanStore) -> None:
    add_resource(store, DATA_LAKE, resource_type=ResourceType.S3_BUCKET)
    full_coverage(store)
    report = ImpactService(store).blast_radius(DATA_LAKE)

    assert report.dependents == ()
    assert report.risk is RiskLevel.LOW


def test_no_dependents_with_missing_coverage_is_medium_not_low(store: ScanStore) -> None:
    add_resource(store, DATA_LAKE, resource_type=ResourceType.S3_BUCKET)
    add_coverage(store, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.AWS_RESOURCES, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.CLOUDTRAIL, CoverageStatus.NOT_REQUESTED)
    report = ImpactService(store).blast_radius(DATA_LAKE)

    assert report.risk is RiskLevel.MEDIUM
    assert any("cloudtrail" in note and "absence of evidence" in note for note in report.notes)


def test_terraform_subject_needs_only_the_declared_side_for_low(store: ScanStore) -> None:
    # Only Terraform relationships can target a Terraform-namespace subject,
    # so a consulted state file is enough to rule out dependents.
    add_resource(store, TF_WEB, provider="terraform", resource_type=ResourceType.EC2_INSTANCE)
    add_coverage(store, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    report = ImpactService(store).blast_radius(TF_WEB)

    assert report.risk is RiskLevel.LOW


def test_latest_coverage_record_decides_the_risk(store: ScanStore) -> None:
    add_resource(store, DATA_LAKE, resource_type=ResourceType.S3_BUCKET)
    full_coverage(store)
    add_coverage(store, EvidenceSource.CLOUDTRAIL, CoverageStatus.UNAVAILABLE)  # more recent
    report = ImpactService(store).blast_radius(DATA_LAKE)

    assert report.risk is RiskLevel.MEDIUM


# --- determinism and stable JSON ------------------------------------------------------


def test_report_is_deterministic_and_json_is_stable(store: ScanStore) -> None:
    add_resource(store, WEB_SG, resource_type=ResourceType.SECURITY_GROUP)
    add_candidate(store, source=WEB, target=WEB_SG, evidence_id="aws:1")
    add_candidate(store, source=BATCH, target=WEB, evidence_id="aws:2")
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=Conclusion.UNDOCUMENTED,
    )

    service = ImpactService(store)
    first, second = service.blast_radius(WEB_SG), service.blast_radius(WEB_SG)
    assert first == second
    assert stable_json(first) == stable_json(second)

    parsed = json.loads(stable_json(first))
    assert parsed["subject_canonical_id"] == WEB_SG
    assert parsed["risk"] == "high"
    assert [dependent["canonical_id"] for dependent in parsed["dependents"]] == [WEB, BATCH]
    assert set(parsed["dependents"][0]) == {
        "canonical_id",
        "path",
        "depth",
        "kind",
        "conclusion",
        "provenance",
        "evidence_ids",
    }
    assert "computed_at" not in parsed  # no timestamps: byte-stable by construction


# --- the why report -------------------------------------------------------------------


def test_why_shows_relationships_evidence_findings_and_limitations(store: ScanStore) -> None:
    add_resource(store, WEB, resource_type=ResourceType.EC2_INSTANCE)
    add_candidate(store, source=WEB, target=WEB_SG, evidence_id="aws:1")
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=Conclusion.UNDOCUMENTED,
    )
    add_coverage(store, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    add_coverage(store, EvidenceSource.AWS_RESOURCES, CoverageStatus.UNAVAILABLE)
    report = WhyService(store).explain(WEB)

    assert report is not None
    assert report.resource.canonical_id == WEB
    assert [relationship.target_canonical_id for relationship in report.outgoing] == [WEB_SG]
    assert report.incoming == ()
    assert [record.evidence.id for record in report.evidence] == ["aws:1"]
    assert [finding.conclusion for finding in report.findings] == [Conclusion.UNDOCUMENTED]
    assert any("aws_resources: unavailable" in line for line in report.limitations)
    assert any("cloudtrail: never requested" in line for line in report.limitations)
    assert not any("terraform_state" in line for line in report.limitations)  # it was available

    text = render_why(report)
    assert text.startswith(f"reality: why {WEB}\n")
    assert f"-> {WEB_SG} attached_to [aws_observed] evidence: aws:1" in text
    assert "undocumented - test finding: undocumented" in text
    assert "coverage limitations" in text


def test_why_unknown_resource_returns_none(store: ScanStore) -> None:
    assert WhyService(store).explain("aws/ec2/instance/-/-/i-0nope") is None


def test_why_with_all_sources_available_has_no_limitations(store: ScanStore) -> None:
    add_resource(store, WEB, resource_type=ResourceType.EC2_INSTANCE)
    full_coverage(store)
    report = WhyService(store).explain(WEB)

    assert report is not None
    assert report.limitations == ()
    assert "none; every discovery source was available" in render_why(report)


# --- the CLI commands ------------------------------------------------------------------


def seed_database(tmp_path: Path) -> Path:
    """A database with one subject, one dependent, one finding, one gap."""
    database = tmp_path / "cli.db"
    conn = connect(database)
    migrate(conn)
    store = ScanStore(conn)
    add_resource(store, WEB)
    subject_with_dependent(store)
    add_finding(
        store,
        source=WEB,
        target=WEB_SG,
        rel_type=RelationshipType.ATTACHED_TO,
        conclusion=Conclusion.UNDOCUMENTED,
    )
    add_coverage(store, EvidenceSource.TERRAFORM_STATE, CoverageStatus.AVAILABLE)
    conn.close()
    return database


class TestWhyCommand:
    def test_prints_the_report_and_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = seed_database(tmp_path)
        # `why WEB` shows its outgoing dependency, the finding about it, and
        # the coverage limitations that bound the conclusion.
        exit_code = cli.main(["--database", str(database), "why", WEB])
        assert exit_code == cli.EXIT_OK
        out = capsys.readouterr().out
        assert out.startswith(f"reality: why {WEB}\n")
        assert f"-> {WEB_SG} attached_to [aws_observed] evidence: aws:1" in out
        assert "undocumented - test finding: undocumented" in out
        assert "coverage limitations" in out

    def test_unknown_resource_is_rejected(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = seed_database(tmp_path)
        exit_code = cli.main(["--database", str(database), "why", "aws/ec2/instance/-/-/i-0nope"])
        assert exit_code == cli.EXIT_INPUT
        assert "resource not found" in capsys.readouterr().err

    def test_missing_database_is_rejected(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = cli.main(["--database", str(tmp_path / "nope.db"), "why", WEB_SG])
        assert exit_code == cli.EXIT_INPUT
        assert "database not found" in capsys.readouterr().err


class TestImpactCommand:
    def test_human_output_names_the_risk(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = seed_database(tmp_path)
        exit_code = cli.main(["--database", str(database), "impact", WEB_SG])
        assert exit_code == cli.EXIT_OK
        out = capsys.readouterr().out
        assert out.startswith(f"reality: impact of {WEB_SG}")
        assert "risk: high" in out
        assert f"- {WEB} (depth 1, undocumented)" in out
        assert f"path: {WEB_SG} -> {WEB}" in out

    def test_json_output_is_parseable_and_stable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        database = seed_database(tmp_path)
        first = cli.main(["--database", str(database), "impact", WEB_SG, "--json"])
        assert first == cli.EXIT_OK
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["risk"] == "high"
        assert parsed["basis"] == "discovery_graph"
        assert parsed["depth"] == DEFAULT_DEPTH

    def test_depth_must_be_positive(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            cli.main(["impact", WEB_SG, "--depth", "0"])
        assert exc.value.code == cli.EXIT_USAGE
