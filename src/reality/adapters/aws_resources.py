"""Read-only AWS resource adapter.

Discovers live EC2 instances, Lambda functions, RDS DB instances, S3 buckets,
and security groups through boto3 clients the caller injects. The only APIs
ever called are STS ``GetCallerIdentity`` (for the account identity that
anchors every canonical ID) and read/list/describe operations on the five
resource services — :data:`ALLOWED_OPERATIONS` is the complete set, and tests
enforce that nothing outside it is invoked. boto3 is an optional dependency,
imported lazily inside the default client factory; with clients injected,
this module needs no AWS SDK at all.

Failure semantics: an access-denied or unavailable response from one service
becomes ``Coverage(UNAVAILABLE)`` for that service while the scan continues
(partial results from the failed service are discarded — they must not look
like complete observations); anything unexpected propagates. If STS itself
fails, ``collect`` raises :class:`AdapterError`: without the account identity
no observation could be safely attributed, so nothing is reported.

S3 is global: bucket observations carry no region (the ``BucketRegion`` the
API reports is deliberately ignored) and no synthesized ARN, while the S3
coverage record notes the selected scan context.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, NamedTuple

from reality.adapters.base import Adapter, AdapterError, AdapterResult
from reality.config import ConfigError, RealityConfig
from reality.domain.enums import (
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.ids import (
    CanonicalId,
    IdParseError,
    canonical_from_native,
    parse_arn,
    unresolved,
)
from reality.domain.models import Coverage, Evidence, Relationship, Resource

#: The complete set of operations this adapter may invoke. STS identity plus
#: read/list/describe only — never anything that mutates.
ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    {
        "get_caller_identity",
        "describe_instances",
        "describe_security_groups",
        "list_functions",
        "describe_db_instances",
        "list_buckets",
    }
)

#: Error codes that mean "this service refused or could not serve the request".
ACCESS_DENIED_CODES: frozenset[str] = frozenset(
    {
        "AccessDeniedException",
        "AccessDenied",
        "UnauthorizedOperation",
        "UnauthorizedAccess",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "ExpiredTokenException",
        "ExpiredToken",
        "RequestExpired",
        "SignatureDoesNotMatch",
        "MissingAuthenticationToken",
    }
)

#: Error codes that mean "the service was temporarily unavailable".
UNAVAILABLE_CODES: frozenset[str] = frozenset(
    {
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "SlowDown",
    }
)

#: Builds the client for one AWS service. Typed as ``Any`` so the adapter
#: type-checks without boto3's stubs installed.
ClientFactory = Callable[[str], Any]


def _default_client_factory(profile: str, region: str) -> ClientFactory:
    """Build real clients from an explicitly selected profile and region.

    boto3 is imported here — inside the factory, never at module level —
    because it is an optional extra; with clients injected, it is not needed.
    """

    def create(service_name: str) -> Any:
        import boto3

        return boto3.Session(profile_name=profile, region_name=region).client(service_name)

    return create


def _error_code(err: BaseException) -> str | None:
    """Extract a botocore ``ClientError``-style code without importing botocore.

    Real ``ClientError`` carries ``err.response["Error"]["Code"]``; anything
    shaped like that is treated the same, which lets tests use plain fakes.
    """
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = error.get("Code")
            if isinstance(code, str) and code:
                return code
    return None


def _expected_failure_code(err: BaseException) -> str | None:
    """The error code when ``err`` is an access-denied/unavailable failure.

    ``None`` means the error is unexpected and must propagate untouched —
    this adapter never swallows what it does not recognize.
    """
    code = _error_code(err)
    if code is not None and (code in ACCESS_DENIED_CODES or code in UNAVAILABLE_CODES):
        return code
    return None


def _string(container: dict[str, Any], key: str, locator: str) -> str:
    """Read a required string field from an API response, naming its locator."""
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"API response at {locator} has no usable '{key}'", locator)
    return value


def _name_tag(tags: Any) -> str | None:
    """The value of the ``Name`` tag, if present; other tags are not stored."""
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            value = tag.get("Value")
            if isinstance(value, str) and value.strip():
                return value
    return None


def _paginate(
    operation: Callable[..., dict[str, Any]], request_key: str, response_key: str
) -> Iterator[dict[str, Any]]:
    """Yield every page, feeding each response token back as the next request."""
    params: dict[str, Any] = {}
    while True:
        page = operation(**params)
        yield page
        token = page.get(response_key)
        if not token:
            return
        params[request_key] = token


class _Outcome(NamedTuple):
    """What one service collector produced, plus its coverage record."""

    resources: list[Resource]
    relationships: list[Relationship]
    evidence: list[Evidence]
    coverage: Coverage


class AwsResourcesAdapter(Adapter):
    """Discovers live AWS resources through injected read-only clients."""

    name = "aws_resources"

    def __init__(
        self,
        *,
        profile: str,
        region: str,
        client_factory: ClientFactory | None = None,
    ) -> None:
        # The explicit profile/region gate comes before anything else: no
        # client may be constructed without a caller-supplied selection.
        if not profile or not profile.strip():
            raise ConfigError(
                "an explicit AWS profile is required before any client is constructed; "
                "no default profile is ever assumed"
            )
        if not region or not region.strip():
            raise ConfigError(
                "an explicit AWS region is required before any client is constructed; "
                "no default region is ever assumed"
            )
        self._profile = profile
        self._region = region
        self._client_factory: ClientFactory = client_factory or _default_client_factory(
            profile, region
        )

    @classmethod
    def from_config(
        cls, config: RealityConfig, client_factory: ClientFactory | None = None
    ) -> AwsResourcesAdapter:
        """Build the adapter behind the Prompt 1 opt-in configuration."""
        config.require_aws()
        profile = config.aws_profile
        region = config.aws_region
        if profile is None or region is None:  # pragma: no cover - require_aws rejects this
            raise ConfigError("require_aws() must run before building the adapter")
        return cls(profile=profile, region=region, client_factory=client_factory)

    # --- entry point --------------------------------------------------------

    def collect(self) -> AdapterResult:
        account, principal = self._caller_identity()
        scan_at = datetime.now(UTC)
        resources: list[Resource] = []
        relationships: list[Relationship] = []
        evidence: list[Evidence] = []
        coverage = [
            Coverage(
                source=EvidenceSource.AWS_RESOURCES,
                status=CoverageStatus.AVAILABLE,
                reason=(
                    f"sts GetCallerIdentity: account {account}, principal {principal} "
                    f"(scan profile {self._profile!r}, selected region {self._region!r})"
                ),
                region=self._region,
            )
        ]
        for label, run in (
            ("ec2 DescribeInstances", self._scan_instances),
            ("ec2 DescribeSecurityGroups", self._scan_security_groups),
            ("lambda ListFunctions", self._scan_functions),
            ("rds DescribeDBInstances", self._scan_db_instances),
            ("s3 ListBuckets", self._scan_buckets),
        ):
            outcome = self._isolated(label, run, account, principal, scan_at)
            resources.extend(outcome.resources)
            relationships.extend(outcome.relationships)
            evidence.extend(outcome.evidence)
            coverage.append(outcome.coverage)
        return AdapterResult(
            resources=tuple(resources),
            relationships=tuple(relationships),
            evidence=tuple(evidence),
            coverage=tuple(coverage),
        )

    def _isolated(
        self,
        label: str,
        run: Callable[[str, str, datetime], _Outcome],
        account: str,
        principal: str,
        scan_at: datetime,
    ) -> _Outcome:
        """Run one service collector; expected failures degrade to UNAVAILABLE.

        An access-denied or unavailable response discards that service's
        partial results (they must not look like complete observations) and
        yields a coverage record; anything unexpected propagates.
        """
        try:
            return run(account, principal, scan_at)
        except Exception as err:
            code = _expected_failure_code(err)
            if code is None:
                raise
            return _Outcome(
                [],
                [],
                [],
                Coverage(
                    source=EvidenceSource.AWS_RESOURCES,
                    status=CoverageStatus.UNAVAILABLE,
                    reason=(
                        f"{label} could not be consulted ({code}); "
                        "unavailable is a property of this source, never a "
                        "conclusion of 'no dependency'"
                    ),
                    region=self._region,
                ),
            )

    def _caller_identity(self) -> tuple[str, str]:
        """Establish the account context every canonical ID is anchored to.

        Failure here is fatal to the whole scan: without an account identity,
        nothing observed could be safely attributed to anyone.
        """
        try:
            response = self._client_factory("sts").get_caller_identity()
        except Exception as err:
            code = _error_code(err)
            detail = f" ({code})" if code else ""
            raise AdapterError(
                f"sts GetCallerIdentity failed{detail}: no account context, "
                "so nothing from this scan can be safely attributed"
            ) from err
        account = response.get("Account")
        principal = response.get("Arn")
        if not isinstance(account, str) or not account.strip():
            raise AdapterError("sts GetCallerIdentity returned no account")
        principal_text = (
            principal if isinstance(principal, str) and principal.strip() else "unknown"
        )
        return account, principal_text

    # --- service collectors -------------------------------------------------

    def _scan_instances(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
        client = self._client_factory("ec2")
        resources: list[Resource] = []
        relationships: list[Relationship] = []
        evidence: list[Evidence] = []
        for page in _paginate(client.describe_instances, "NextToken", "NextToken"):
            reservations = page.get("Reservations") or []
            for res_index, reservation in enumerate(reservations):
                for inst_index, raw in enumerate(reservation.get("Instances") or []):
                    locator = (
                        f"ec2:DescribeInstances#Reservations[{res_index}].Instances[{inst_index}]"
                    )
                    instance_id = _string(raw, "InstanceId", locator)
                    canonical = canonical_from_native(
                        "ec2", "instance", instance_id, region=self._region, account=account
                    )
                    resources.append(
                        Resource(
                            canonical_id=canonical.key,
                            resource_type=ResourceType.EC2_INSTANCE,
                            provider=canonical.provider,
                            native_id=instance_id,
                            region=self._region,
                            account=account,
                            name=_name_tag(raw.get("Tags")),
                            discovered_at=scan_at,
                            source=EvidenceSource.AWS_RESOURCES,
                        )
                    )
                    for sg_index, sg in enumerate(raw.get("SecurityGroups") or []):
                        sg_locator = f"{locator}.SecurityGroups[{sg_index}]"
                        group_id = _string(sg, "GroupId", sg_locator)
                        target = canonical_from_native(
                            "ec2", "security-group", group_id, region=self._region, account=account
                        )
                        self._link(
                            source=canonical,
                            source_ref=instance_id,
                            target=target,
                            target_ref=group_id,
                            relationship_type=RelationshipType.ATTACHED_TO,
                            service="ec2",
                            operation="DescribeInstances",
                            attribute="SecurityGroups",
                            locator=sg_locator,
                            principal=principal,
                            scan_at=scan_at,
                            relationships=relationships,
                            evidence=evidence,
                        )
        return _Outcome(
            resources,
            relationships,
            evidence,
            self._available_coverage("ec2 DescribeInstances", f"{len(resources)} instance(s)"),
        )

    def _scan_security_groups(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
        client = self._client_factory("ec2")
        resources: list[Resource] = []
        for page in _paginate(client.describe_security_groups, "NextToken", "NextToken"):
            groups = page.get("SecurityGroups") or []
            for sg_index, raw in enumerate(groups):
                locator = f"ec2:DescribeSecurityGroups#SecurityGroups[{sg_index}]"
                group_id = _string(raw, "GroupId", locator)
                canonical = canonical_from_native(
                    "ec2", "security-group", group_id, region=self._region, account=account
                )
                resources.append(
                    Resource(
                        canonical_id=canonical.key,
                        resource_type=ResourceType.SECURITY_GROUP,
                        provider=canonical.provider,
                        native_id=group_id,
                        region=self._region,
                        account=account,
                        name=_string(raw, "GroupName", locator),
                        discovered_at=scan_at,
                        source=EvidenceSource.AWS_RESOURCES,
                    )
                )
        return _Outcome(
            resources,
            [],
            [],
            self._available_coverage(
                "ec2 DescribeSecurityGroups", f"{len(resources)} security group(s)"
            ),
        )

    def _scan_functions(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
        client = self._client_factory("lambda")
        resources: list[Resource] = []
        relationships: list[Relationship] = []
        evidence: list[Evidence] = []
        for page in _paginate(client.list_functions, "Marker", "NextMarker"):
            functions = page.get("Functions") or []
            for fn_index, raw in enumerate(functions):
                locator = f"lambda:ListFunctions#Functions[{fn_index}]"
                function_name = _string(raw, "FunctionName", locator)
                function_arn = _string(raw, "FunctionArn", locator)
                canonical = self._canonical_from_arn(
                    function_arn, "lambda", "function", function_name, account
                )
                resources.append(
                    Resource(
                        canonical_id=canonical.key,
                        resource_type=ResourceType.LAMBDA_FUNCTION,
                        provider=canonical.provider,
                        native_id=function_name,
                        arn=function_arn,
                        region=canonical.region,
                        account=canonical.account or account,
                        name=function_name,
                        discovered_at=scan_at,
                        source=EvidenceSource.AWS_RESOURCES,
                    )
                )
                role = raw.get("Role")
                if isinstance(role, str) and role:
                    role_locator = f"{locator}.Role"
                    try:
                        target = parse_arn(role)
                    except IdParseError:
                        target = unresolved(role)
                    self._link(
                        source=canonical,
                        source_ref=function_name,
                        target=target,
                        target_ref=role,
                        relationship_type=RelationshipType.PERMISSION_ON,
                        service="lambda",
                        operation="ListFunctions",
                        attribute="Role",
                        locator=role_locator,
                        principal=principal,
                        scan_at=scan_at,
                        relationships=relationships,
                        evidence=evidence,
                    )
        return _Outcome(
            resources,
            relationships,
            evidence,
            self._available_coverage("lambda ListFunctions", f"{len(resources)} function(s)"),
        )

    def _scan_db_instances(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
        client = self._client_factory("rds")
        resources: list[Resource] = []
        relationships: list[Relationship] = []
        evidence: list[Evidence] = []
        for page in _paginate(client.describe_db_instances, "Marker", "Marker"):
            databases = page.get("DBInstances") or []
            for db_index, raw in enumerate(databases):
                locator = f"rds:DescribeDBInstances#DBInstances[{db_index}]"
                identifier = _string(raw, "DBInstanceIdentifier", locator)
                db_arn = _string(raw, "DBInstanceArn", locator)
                canonical = self._canonical_from_arn(db_arn, "rds", "db", identifier, account)
                resources.append(
                    Resource(
                        canonical_id=canonical.key,
                        resource_type=ResourceType.RDS_DB_INSTANCE,
                        provider=canonical.provider,
                        native_id=identifier,
                        arn=db_arn,
                        region=canonical.region,
                        account=canonical.account or account,
                        name=identifier,
                        discovered_at=scan_at,
                        source=EvidenceSource.AWS_RESOURCES,
                    )
                )
                for sg_index, sg in enumerate(raw.get("VpcSecurityGroups") or []):
                    sg_locator = f"{locator}.VpcSecurityGroups[{sg_index}]"
                    group_id = _string(sg, "VpcSecurityGroupId", sg_locator)
                    target = canonical_from_native(
                        "ec2", "security-group", group_id, region=self._region, account=account
                    )
                    self._link(
                        source=canonical,
                        source_ref=identifier,
                        target=target,
                        target_ref=group_id,
                        relationship_type=RelationshipType.ATTACHED_TO,
                        service="rds",
                        operation="DescribeDBInstances",
                        attribute="VpcSecurityGroups",
                        locator=sg_locator,
                        principal=principal,
                        scan_at=scan_at,
                        relationships=relationships,
                        evidence=evidence,
                    )
        return _Outcome(
            resources,
            relationships,
            evidence,
            self._available_coverage("rds DescribeDBInstances", f"{len(resources)} DB instance(s)"),
        )

    def _scan_buckets(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
        client = self._client_factory("s3")
        response = client.list_buckets()
        resources: list[Resource] = []
        buckets = response.get("Buckets") or []
        for index, raw in enumerate(buckets):
            locator = f"s3:ListBuckets#Buckets[{index}]"
            bucket_name = _string(raw, "Name", locator)
            # Buckets are global: no region is attached — not even the
            # BucketRegion the API reports — and no ARN is synthesized. The
            # scan context (account, profile, selected region) is recorded in
            # the coverage note below, not in the bucket's identity.
            canonical = canonical_from_native(
                "s3", "bucket", bucket_name, region=None, account=account
            )
            resources.append(
                Resource(
                    canonical_id=canonical.key,
                    resource_type=ResourceType.S3_BUCKET,
                    provider=canonical.provider,
                    native_id=bucket_name,
                    region=None,
                    account=account,
                    name=bucket_name,
                    discovered_at=scan_at,
                    source=EvidenceSource.AWS_RESOURCES,
                )
            )
        return _Outcome(
            resources,
            [],
            [],
            Coverage(
                source=EvidenceSource.AWS_RESOURCES,
                status=CoverageStatus.AVAILABLE,
                reason=(
                    f"s3 ListBuckets: {len(resources)} bucket(s) observed; buckets are global "
                    "and carry no region — "
                    f"scan context: profile {self._profile!r}, selected region {self._region!r}"
                ),
                region=self._region,
            ),
        )

    # --- shared helpers -----------------------------------------------------

    def _available_coverage(self, label: str, summary: str) -> Coverage:
        return Coverage(
            source=EvidenceSource.AWS_RESOURCES,
            status=CoverageStatus.AVAILABLE,
            reason=f"{label}: {summary}",
            region=self._region,
        )

    def _canonical_from_arn(
        self, arn: str, service: str, resource_type: str, native_id: str, account: str
    ) -> CanonicalId:
        """The ARN is authoritative; the native ID plus scan context is the fallback."""
        try:
            return parse_arn(arn)
        except IdParseError:
            return canonical_from_native(
                service, resource_type, native_id, region=self._region, account=account
            )

    def _link(
        self,
        *,
        source: CanonicalId,
        source_ref: str,
        target: CanonicalId,
        target_ref: str,
        relationship_type: RelationshipType,
        service: str,
        operation: str,
        attribute: str,
        locator: str,
        principal: str,
        scan_at: datetime,
        relationships: list[Relationship],
        evidence: list[Evidence],
    ) -> None:
        """Record one AWS-reported topology link plus the evidence backing it."""
        evidence_id = (
            f"aws:{service}:{operation}:{source_ref}:"
            f"{relationship_type.value}:{attribute}:{target_ref}"
        )
        evidence.append(
            Evidence(
                id=evidence_id,
                source=EvidenceSource.AWS_RESOURCES,
                type=EvidenceType.OBSERVED_ATTRIBUTE,
                observed_at=scan_at,
                actor=principal,
                source_ref=source_ref,
                target_ref=target_ref,
                source_canonical_id=source.key,
                target_canonical_id=target.key,
                strength=EvidenceStrength.HIGH,
                # every locator already carries its "service:Operation#" prefix
                raw_locator=locator,
                explanation=(
                    f"AWS {operation} directly reports '{attribute}' = {target_ref!r} "
                    f"on {source_ref}"
                ),
            )
        )
        relationships.append(
            Relationship(
                source_canonical_id=source.key,
                target_canonical_id=target.key,
                type=relationship_type,
                origin=RelationshipOrigin.AWS_OBSERVED,
                evidence_ids=(evidence_id,),
            )
        )
