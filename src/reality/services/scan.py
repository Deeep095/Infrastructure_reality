"""The scan orchestrator: selected sources in, one transactional scan out.

This module wires the adapters together without adding conclusions of its
own — no findings, no impact, no reconciliation. Its contract:

- **Requested vs not.** What is requested is decided entirely by
  construction: the offline Terraform adapter is always available, and each
  AWS-side adapter is handed in only when the user explicitly opted in (see
  :meth:`ScanService.from_config`). A source that was not requested is
  reported and recorded as ``NOT_REQUESTED`` — never as "no dependencies".
- **Partial evidence is success.** A source that fails (access denied,
  throttled, exhausted) becomes ``UNAVAILABLE`` coverage while the scan
  completes with reduced coverage. Only unexpected errors propagate.
- **Invalid local input aborts.** A Terraform path that cannot be read or
  parsed is a user error, not reduced coverage: the scan refuses before
  anything is written (:class:`ScanInputError`).
- **One scan, one transaction.** Everything a scan collects is written
  through :meth:`ScanStore.scan` — commit on success, roll back on error.
- **Identity joins live inside the scan.** When a single scan observed both
  the declared and the observed world, it computes the evidence-backed
  identity mappings joining them (:mod:`reality.services.identity`) and
  writes them in the same transaction, so a mapping is always anchored to a
  scan that saw both sides.
- **Read-only.** The orchestrator runs no Terraform command, constructs no
  boto3 client itself, and touches nothing outside the SQLite database.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reality.adapters.aws_resources import AwsResourcesAdapter, ClientFactory
from reality.adapters.base import Adapter, AdapterError, AdapterResult
from reality.adapters.cloudtrail import CloudTrailAdapter
from reality.adapters.iam import IamAdapter
from reality.adapters.terraform import TerraformAdapter
from reality.config import ConfigError, RealityConfig
from reality.domain.enums import CoverageStatus, EvidenceSource
from reality.domain.models import Coverage
from reality.services.identity import compute_identity_mappings
from reality.storage.repositories import ScanSession, ScanStore


class ScanInputError(Exception):
    """A user-supplied local input is invalid; nothing was scanned."""


class SourceReport(BaseModel):
    """One source's outcome in a scan: its adapter name, status, and detail."""

    model_config = ConfigDict(frozen=True)

    source: str
    status: CoverageStatus
    detail: str


class ScanReport(BaseModel):
    """What one scan did, for the CLI to print and tests to assert on."""

    model_config = ConfigDict(frozen=True)

    scan_run_id: int
    region: str | None = None
    account: str | None = None
    sources: tuple[SourceReport, ...] = ()
    resources: int = 0
    relationships: int = 0
    evidence: int = 0
    coverage: int = 0
    identity_mappings: int = 0


class ScanService:
    """Runs the selected read-only sources and writes one scan transactionally."""

    def __init__(
        self,
        store: ScanStore,
        *,
        terraform: TerraformAdapter | None = None,
        aws_resources: AwsResourcesAdapter | None = None,
        iam: IamAdapter | None = None,
        cloudtrail: CloudTrailAdapter | None = None,
        region: str | None = None,
    ) -> None:
        self._store = store
        self._terraform = terraform if terraform is not None else TerraformAdapter()
        self._aws_sources: tuple[tuple[str, Adapter | None, EvidenceSource], ...] = (
            ("aws_resources", aws_resources, EvidenceSource.AWS_RESOURCES),
            ("iam", iam, EvidenceSource.IAM),
            ("cloudtrail", cloudtrail, EvidenceSource.CLOUDTRAIL),
        )
        self._region = region

    @classmethod
    def from_config(
        cls,
        config: RealityConfig,
        store: ScanStore,
        *,
        cloudtrail_window: tuple[datetime, datetime] | None = None,
        client_factory: ClientFactory | None = None,
    ) -> ScanService:
        """Build a service honouring the AWS opt-in contract.

        Unless the complete explicit opt-in triple (``--aws --profile
        --region``) is present in the config, no AWS-side adapter is
        constructed at all, so no boto3 client can ever be created. The
        CloudTrail adapter additionally requires an explicit bounded window:
        without one it stays unrequested rather than guessing a range.
        """
        aws_resources: AwsResourcesAdapter | None = None
        iam: IamAdapter | None = None
        cloudtrail: CloudTrailAdapter | None = None
        region: str | None = None
        if config.aws_ready:
            aws_resources = AwsResourcesAdapter.from_config(config, client_factory=client_factory)
            iam = IamAdapter.from_config(config, client_factory=client_factory)
            if cloudtrail_window is not None:
                start, end = cloudtrail_window
                cloudtrail = CloudTrailAdapter.from_config(
                    config, client_factory=client_factory, start=start, end=end
                )
            region = config.aws_region
        return cls(
            store,
            aws_resources=aws_resources,
            iam=iam,
            cloudtrail=cloudtrail,
            region=region,
        )

    # --- entry point ----------------------------------------------------------

    def run(self, terraform_paths: Sequence[Path | str] = ()) -> ScanReport:
        """Collect every requested source and persist one scan run."""
        paths = [Path(p) for p in terraform_paths]
        if not paths and not any(adapter is not None for _, adapter, _ in self._aws_sources):
            raise ConfigError(
                "nothing to scan: pass at least one Terraform JSON path, or opt into "
                "AWS with --aws --profile PROFILE --region REGION"
            )

        # Local inputs first: an invalid path aborts before anything is written.
        terraform_results = [self._parse_local(path) for path in paths]

        # Opted-in AWS-side sources. An adapter-level failure is coverage
        # (UNAVAILABLE), not a crash: the scan succeeds with reduced coverage.
        aws_results: list[tuple[str, EvidenceSource, AdapterResult]] = []
        for label, adapter, source in self._aws_sources:
            if adapter is None:
                continue
            try:
                aws_results.append((label, source, adapter.collect()))
            except AdapterError as err:
                aws_results.append(
                    (
                        label,
                        source,
                        AdapterResult(
                            coverage=(
                                Coverage(
                                    source=source,
                                    status=CoverageStatus.UNAVAILABLE,
                                    reason=f"the {label} adapter could not complete: {err}",
                                ),
                            )
                        ),
                    )
                )

        results = [*terraform_results, *(result for _, _, result in aws_results)]
        not_requested = self._not_requested_coverage(paths)
        anchor = self._anchor_source(terraform_results, aws_results)
        account = next(
            (
                resource.account
                for result in results
                for resource in result.resources
                if resource.account is not None
            ),
            None,
        )

        with self._store.scan(source=anchor, region=self._region, account=account) as session:
            run_id = session.scan_run_id
            for result in results:
                self._persist(session, result)
            # Identity joins are computed from this scan's own resources —
            # both sides of every join were observed by this run alone.
            mappings = compute_identity_mappings(
                [resource for result in results for resource in result.resources]
            )
            for computed in mappings:
                session.upsert_evidence(computed.evidence)
                session.add_identity_mapping(computed.mapping)
            for record in not_requested:
                session.add_coverage(record)

        return ScanReport(
            scan_run_id=run_id,
            region=self._region,
            account=account,
            sources=self._source_reports(paths, terraform_results, aws_results),
            resources=sum(len(result.resources) for result in results),
            relationships=sum(len(result.relationships) for result in results),
            evidence=sum(len(result.evidence) for result in results) + len(mappings),
            coverage=sum(len(result.coverage) for result in results) + len(not_requested),
            identity_mappings=len(mappings),
        )

    # --- collection helpers ---------------------------------------------------

    def _parse_local(self, path: Path) -> AdapterResult:
        """Parse one local Terraform JSON document or refuse the whole scan.

        The adapter degrades a bad file to ``UNAVAILABLE`` coverage rather
        than raising; here that is the signal to stop — an invalid local
        input is a user error, not reduced coverage, and nothing is written.
        """
        result = self._terraform.parse_file(path)
        rejection = next(
            (record for record in result.coverage if record.status == CoverageStatus.UNAVAILABLE),
            None,
        )
        if rejection is not None:
            raise ScanInputError(rejection.reason)
        return result

    def _not_requested_coverage(self, paths: Sequence[Path]) -> tuple[Coverage, ...]:
        """Coverage records for sources this scan never consulted."""
        records: list[Coverage] = []
        if not paths:
            records.append(
                Coverage(
                    source=EvidenceSource.TERRAFORM_STATE,
                    status=CoverageStatus.NOT_REQUESTED,
                    reason=(
                        "no local Terraform JSON paths were given; "
                        "declared infrastructure was not consulted"
                    ),
                )
            )
        aws_opted_in = any(adapter is not None for _, adapter, _ in self._aws_sources)
        for label, adapter, source in self._aws_sources:
            if adapter is not None:
                continue
            if label == "cloudtrail" and aws_opted_in:
                reason = (
                    "no CloudTrail lookup window was selected; "
                    "recent API activity was not consulted"
                )
            else:
                reason = (
                    f"the {label} source was not requested: AWS was not opted in with "
                    "--aws --profile PROFILE --region REGION, so it was not consulted"
                )
            records.append(
                Coverage(source=source, status=CoverageStatus.NOT_REQUESTED, reason=reason)
            )
        return tuple(records)

    @staticmethod
    def _anchor_source(
        terraform_results: list[AdapterResult],
        aws_results: list[tuple[str, EvidenceSource, AdapterResult]],
    ) -> EvidenceSource:
        """The scan run's recorded origin: the declared world when Terraform
        was scanned (state preferred over plan), otherwise the first
        requested AWS-side source."""
        if terraform_results:
            kinds = {record.source for result in terraform_results for record in result.coverage}
            if (
                EvidenceSource.TERRAFORM_PLAN in kinds
                and EvidenceSource.TERRAFORM_STATE not in kinds
            ):
                return EvidenceSource.TERRAFORM_PLAN
            return EvidenceSource.TERRAFORM_STATE
        return aws_results[0][1]

    # --- persistence ------------------------------------------------------------

    @staticmethod
    def _persist(session: ScanSession, result: AdapterResult) -> None:
        for resource in result.resources:
            session.upsert_resource(resource)
        for evidence in result.evidence:
            session.upsert_evidence(evidence)
        for relationship in result.relationships:
            session.upsert_relationship(relationship, relationship.evidence_ids)
        for change in result.terraform_changes:
            session.upsert_terraform_address(change)
        for record in result.coverage:
            session.add_coverage(record)

    # --- reporting ---------------------------------------------------------------

    def _source_reports(
        self,
        paths: Sequence[Path],
        terraform_results: list[AdapterResult],
        aws_results: list[tuple[str, EvidenceSource, AdapterResult]],
    ) -> tuple[SourceReport, ...]:
        collected = {label: result for label, _, result in aws_results}
        reports: list[SourceReport] = []
        if terraform_results:
            resources = sum(len(result.resources) for result in terraform_results)
            links = sum(len(result.relationships) for result in terraform_results)
            reports.append(
                SourceReport(
                    source="terraform",
                    status=CoverageStatus.AVAILABLE,
                    detail=(
                        f"{len(paths)} file(s) parsed: {resources} declared resource(s), "
                        f"{links} relationship candidate(s)"
                    ),
                )
            )
        else:
            reports.append(
                SourceReport(
                    source="terraform",
                    status=CoverageStatus.NOT_REQUESTED,
                    detail="no local Terraform JSON paths were given",
                )
            )
        for label, adapter, _ in self._aws_sources:
            if adapter is None:
                reports.append(
                    SourceReport(
                        source=label,
                        status=CoverageStatus.NOT_REQUESTED,
                        detail="not requested for this scan",
                    )
                )
            else:
                reports.append(self._result_report(label, collected[label]))
        return tuple(reports)

    @staticmethod
    def _result_report(label: str, result: AdapterResult) -> SourceReport:
        available = [c for c in result.coverage if c.status == CoverageStatus.AVAILABLE]
        if available:
            detail = (
                f"{len(result.resources)} resource(s), "
                f"{len(result.relationships)} relationship candidate(s), "
                f"{len(result.evidence)} evidence"
            )
            unavailable = len(result.coverage) - len(available)
            if unavailable:
                detail += f"; {unavailable} sub-source(s) unavailable"
            return SourceReport(source=label, status=CoverageStatus.AVAILABLE, detail=detail)
        reason = next(
            (c.reason for c in result.coverage if c.status == CoverageStatus.UNAVAILABLE),
            "the source produced no coverage",
        )
        return SourceReport(source=label, status=CoverageStatus.UNAVAILABLE, detail=reason)
