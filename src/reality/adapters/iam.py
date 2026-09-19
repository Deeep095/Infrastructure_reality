"""Read-only IAM permission-evidence adapter.

Collects IAM roles, their inline role policies, attached managed-policy
metadata, and each managed policy's currently default version using only
List/Get operations — :data:`ALLOWED_OPERATIONS` is the complete set, and
tests enforce that nothing outside it is invoked. boto3 is an optional
dependency, imported lazily inside the default client factory; with clients
injected, this module needs no AWS SDK at all.

Policy documents are parsed defensively: ``Statement`` may be an object or a
list, ``Action``/``Resource`` may be scalars or lists, ``Effect`` must be
exactly ``Allow`` or ``Deny``. Two rules follow from the project's frozen
semantics:

- Every allow is a **POSSIBLE permission candidate, never proof of runtime
  use** — that caveat is written into every allow explanation.
- An explicit ``Deny`` is recorded as evidence but never emitted as a
  ``PERMISSION_ON`` relationship: a deny is the absence of permission, not a
  grant to reconcile later.

Wildcard resources, resources containing policy variables (``${...}``), and
non-ARN strings cannot name a specific target; they are recorded against the
``unresolved`` namespace with LOW (pattern) or UNKNOWN (variable) evidence —
they can never join with a resolved canonical ID. Malformed or inaccessible
policies produce ``Coverage(UNAVAILABLE)`` records; no relationship is ever
invented for them.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from typing import Any

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

#: The complete set of operations this adapter may invoke. List/Get only —
#: never any IAM mutation endpoint.
ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    {
        "list_roles",
        "list_role_policies",
        "get_role_policy",
        "list_attached_role_policies",
        "get_policy",
        "get_policy_version",
    }
)

#: Error codes that mean "this call was refused or could not be served".
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
    """Extract a botocore ``ClientError``-style code without importing botocore."""
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

    ``None`` means the error is unexpected and must propagate untouched.
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


def _string_list(value: Any) -> list[str] | None:
    """A scalar or list of non-empty strings, as IAM writes Action/Resource.

    Returns ``None`` for anything else — a malformed value, never a guess.
    """
    if isinstance(value, str):
        values: list[Any] = [value]
    elif isinstance(value, list):
        values = value
    else:
        return None
    if not all(isinstance(item, str) and item.strip() for item in values):
        return None
    return values


def _parse_policy_document(raw: Any) -> dict[str, Any] | None:
    """Accept a decoded policy object or a JSON string; ``None`` when unusable."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _statements(
    document: dict[str, Any],
) -> tuple[list[tuple[dict[str, Any], int]], int] | None:
    """Statement entries as (statement, original index) pairs plus a malformed count.

    ``None`` means the document has no usable ``Statement`` member at all.
    Non-object entries inside a Statement list count as malformed while the
    usable entries keep their original indices.
    """
    raw = document.get("Statement")
    if isinstance(raw, dict):
        return [(raw, 0)], 0
    if not isinstance(raw, list):
        return None
    pairs: list[tuple[dict[str, Any], int]] = []
    malformed = 0
    for index, entry in enumerate(raw):
        if isinstance(entry, dict):
            pairs.append((entry, index))
        else:
            malformed += 1
    return pairs, malformed


def _target_for(resource: str) -> tuple[CanonicalId, EvidenceStrength, str]:
    """Resolve one policy Resource value to a target, strength, and caveat.

    Wildcards and variables never become resolved canonical IDs — they land
    in the ``unresolved`` namespace where they cannot join with anything.
    """
    if "${" in resource:
        return (
            unresolved(resource),
            EvidenceStrength.UNKNOWN,
            "the resource contains policy variables, so the concrete target "
            "depends on runtime context that cannot be resolved statically",
        )
    if "*" in resource or "?" in resource:
        return (
            unresolved(resource),
            EvidenceStrength.LOW,
            "the resource is a pattern, so no specific target can be identified",
        )
    try:
        return parse_arn(resource), EvidenceStrength.MEDIUM, ""
    except IdParseError:
        return (
            unresolved(resource),
            EvidenceStrength.LOW,
            "the resource is not a normalizable ARN and is recorded unresolved",
        )


class _Sink:
    """Mutable accumulation target for one adapter run (the models stay frozen)."""

    def __init__(self) -> None:
        self.resources: list[Resource] = []
        self.relationships: list[Relationship] = []
        self.evidence: list[Evidence] = []
        self.coverage: list[Coverage] = []


class IamAdapter(Adapter):
    """Collects IAM permission evidence through injected read-only clients."""

    name = "iam"

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
    ) -> IamAdapter:
        """Build the adapter behind the Prompt 1 opt-in configuration."""
        config.require_aws()
        profile = config.aws_profile
        region = config.aws_region
        if profile is None or region is None:  # pragma: no cover - require_aws rejects this
            raise ConfigError("require_aws() must run before building the adapter")
        return cls(profile=profile, region=region, client_factory=client_factory)

    # --- entry point --------------------------------------------------------

    def collect(self) -> AdapterResult:
        client = self._client_factory("iam")
        scan_at = datetime.now(UTC)
        try:
            roles = self._enumerate(client, "list_roles", "Roles")
        except Exception as err:
            code = _expected_failure_code(err)
            if code is None:
                raise
            # Without ListRoles there is nothing this adapter can report; the
            # unavailable record lets the scan continue with other sources.
            return AdapterResult(
                coverage=(
                    self._unavailable(
                        f"iam ListRoles could not be consulted ({code}); "
                        "no roles, policies, or permission candidates were collected"
                    ),
                )
            )
        sink = _Sink()
        for index, role in enumerate(roles):
            self._scan_role(client, role, index, scan_at, sink)
        sink.coverage.append(
            Coverage(
                source=EvidenceSource.IAM,
                status=CoverageStatus.AVAILABLE,
                reason=(
                    f"iam ListRoles: {len(roles)} role(s) consulted; "
                    f"{len(sink.evidence)} policy-statement evidence item(s), "
                    f"{len(sink.relationships)} permission candidate(s); IAM is global — "
                    f"scan context: profile {self._profile!r}, selected region {self._region!r}"
                ),
                region=self._region,
            )
        )
        return AdapterResult(
            resources=tuple(sink.resources),
            relationships=tuple(sink.relationships),
            evidence=tuple(sink.evidence),
            coverage=tuple(sink.coverage),
        )

    # --- per-role scan ------------------------------------------------------

    def _scan_role(
        self, client: Any, role: dict[str, Any], role_index: int, scan_at: datetime, sink: _Sink
    ) -> None:
        locator = f"iam:ListRoles#Roles[{role_index}]"
        role_name = _string(role, "RoleName", locator)
        role_arn = _string(role, "Arn", locator)
        role_id = self._canonical_role(role_arn, role_name)
        sink.resources.append(
            Resource(
                canonical_id=role_id.key,
                resource_type=ResourceType.IAM_ROLE,
                provider=role_id.provider,
                native_id=role_name,
                arn=role_arn,
                region=role_id.region,  # None: IAM is a global service
                account=role_id.account,
                name=role_name,
                discovered_at=scan_at,
                source=EvidenceSource.IAM,
            )
        )
        allow_evidence: dict[str, list[str]] = {}
        inline_names = self._guarded(
            f"inline policies of role {role_name!r}",
            sink,
            partial(
                self._enumerate, client, "list_role_policies", "PolicyNames", RoleName=role_name
            ),
        )
        for policy_name in inline_names or []:
            label = f"inline policy {policy_name!r} of role {role_name!r}"
            response = self._guarded(
                label,
                sink,
                partial(client.get_role_policy, RoleName=role_name, PolicyName=policy_name),
            )
            if response is None:
                continue
            document = _parse_policy_document(response.get("PolicyDocument"))
            if document is None:
                sink.coverage.append(
                    self._unavailable(
                        f"{label} could not be parsed as a policy document; "
                        "no relationship invented for it"
                    )
                )
                continue
            self._process_policy_document(
                document,
                kind="inline",
                role_key=role_id.key,
                policy_label=label,
                policy_id=f"{role_arn}/{policy_name}",
                raw_prefix=f"iam:GetRolePolicy#{role_name}/{policy_name}",
                scan_at=scan_at,
                sink=sink,
                allow_evidence=allow_evidence,
            )
        attached = self._guarded(
            f"attached managed policies of role {role_name!r}",
            sink,
            partial(
                self._enumerate,
                client,
                "list_attached_role_policies",
                "AttachedPolicies",
                RoleName=role_name,
            ),
        )
        for entry in attached or []:
            self._scan_managed_policy(
                client, entry, role_name, role_id, scan_at, sink, allow_evidence
            )
        for target_key in sorted(allow_evidence):
            sink.relationships.append(
                Relationship(
                    source_canonical_id=role_id.key,
                    target_canonical_id=target_key,
                    type=RelationshipType.PERMISSION_ON,
                    origin=RelationshipOrigin.IAM_POLICY,
                    evidence_ids=tuple(sorted(allow_evidence[target_key])),
                )
            )

    def _scan_managed_policy(
        self,
        client: Any,
        entry: dict[str, Any],
        role_name: str,
        role_id: CanonicalId,
        scan_at: datetime,
        sink: _Sink,
        allow_evidence: dict[str, list[str]],
    ) -> None:
        policy_arn = _string(entry, "PolicyArn", f"iam:ListAttachedRolePolicies#{role_name}")
        meta = self._guarded(
            f"managed policy {policy_arn}",
            sink,
            partial(client.get_policy, PolicyArn=policy_arn),
        )
        if meta is None:
            return
        policy = meta.get("Policy")
        if not isinstance(policy, dict):
            sink.coverage.append(
                self._unavailable(
                    f"iam GetPolicy for {policy_arn} returned no policy object; "
                    "no relationship invented for it"
                )
            )
            return
        default_version = _string(policy, "DefaultVersionId", f"iam:GetPolicy#{policy_arn}")
        label = f"managed policy {policy_arn} (default version {default_version})"
        version_response = self._guarded(
            label,
            sink,
            partial(client.get_policy_version, PolicyArn=policy_arn, VersionId=default_version),
        )
        if version_response is None:
            return
        version = version_response.get("PolicyVersion")
        if not isinstance(version, dict):
            sink.coverage.append(
                self._unavailable(
                    f"{label} returned no version object; no relationship invented for it"
                )
            )
            return
        document = _parse_policy_document(version.get("Document"))
        if document is None:
            sink.coverage.append(
                self._unavailable(
                    f"{label} could not be parsed as a policy document; "
                    "no relationship invented for it"
                )
            )
            return
        self._process_policy_document(
            document,
            kind="managed",
            role_key=role_id.key,
            policy_label=label,
            policy_id=f"{policy_arn}@{default_version}",
            raw_prefix=f"iam:GetPolicyVersion#{policy_arn}@{default_version}",
            scan_at=scan_at,
            sink=sink,
            allow_evidence=allow_evidence,
        )

    # --- policy statement processing ----------------------------------------

    def _process_policy_document(
        self,
        document: dict[str, Any],
        *,
        kind: str,
        role_key: str,
        policy_label: str,
        policy_id: str,
        raw_prefix: str,
        scan_at: datetime,
        sink: _Sink,
        allow_evidence: dict[str, list[str]],
    ) -> None:
        statements = _statements(document)
        if statements is None:
            sink.coverage.append(
                self._unavailable(
                    f"{policy_label} has no usable 'Statement' member; "
                    "no relationship invented for it"
                )
            )
            return
        pairs, malformed = statements
        for statement, index in pairs:
            effect = statement.get("Effect")
            if effect not in ("Allow", "Deny"):
                malformed += 1
                continue
            actions = _string_list(statement.get("Action"))
            resources = _string_list(statement.get("Resource"))
            if actions is None or resources is None:
                malformed += 1
                continue
            # dict.fromkeys dedupes while preserving order: a repeated Action or
            # Resource entry inside one statement is one permission, and its
            # evidence ID must stay unique.
            for action in dict.fromkeys(actions):
                for resource in dict.fromkeys(resources):
                    self._emit_pair(
                        effect=effect,
                        action=action,
                        resource=resource,
                        index=index,
                        kind=kind,
                        role_key=role_key,
                        policy_label=policy_label,
                        policy_id=policy_id,
                        raw_prefix=raw_prefix,
                        scan_at=scan_at,
                        sink=sink,
                        allow_evidence=allow_evidence,
                    )
        if malformed:
            sink.coverage.append(
                self._unavailable(
                    f"{policy_label}: {malformed} malformed statement(s) skipped; "
                    "no relationship invented for them"
                )
            )

    def _emit_pair(
        self,
        *,
        effect: str,
        action: str,
        resource: str,
        index: int,
        kind: str,
        role_key: str,
        policy_label: str,
        policy_id: str,
        raw_prefix: str,
        scan_at: datetime,
        sink: _Sink,
        allow_evidence: dict[str, list[str]],
    ) -> None:
        """Record one (action, resource) pair of one statement as evidence.

        Allow pairs additionally accumulate into ``allow_evidence`` for a
        PERMISSION_ON candidate; Deny pairs never do.
        """
        target, strength, note = _target_for(resource)
        evidence_id = f"iam:{kind}:{policy_id}:s{index}:{effect}:{action}:{resource}"
        if effect == "Allow":
            qualifier = "grants"
            caveat = "a POSSIBLE permission candidate, never proof of runtime use"
        else:
            qualifier = "explicitly denies"
            caveat = "a deny is never emitted as a permission candidate"
        explanation = (
            f"IAM {policy_label} statement {index} {qualifier} '{action}' on {resource!r}; {caveat}"
        )
        if note:
            explanation += f"; {note}"
        sink.evidence.append(
            Evidence(
                id=evidence_id,
                source=EvidenceSource.IAM,
                type=EvidenceType.POLICY_STATEMENT,
                observed_at=scan_at,
                actor=policy_id,  # the declaring policy; the role is source_canonical_id
                source_ref=policy_id,
                target_ref=resource,
                source_canonical_id=role_key,
                target_canonical_id=target.key,
                strength=strength,
                raw_locator=f"{raw_prefix}.Statement[{index}]",
                explanation=explanation,
            )
        )
        if effect == "Allow":
            allow_evidence.setdefault(target.key, []).append(evidence_id)

    # --- helpers ------------------------------------------------------------

    def _enumerate(self, client: Any, operation: str, list_key: str, **initial: Any) -> list[Any]:
        """Collect every item across the pages of a Marker-paginated List API."""
        params: dict[str, Any] = dict(initial)
        collected: list[Any] = []
        while True:
            page = getattr(client, operation)(**params)
            items = page.get(list_key)
            if items is not None:
                collected.extend(items)
            marker = page.get("Marker")
            if not marker:
                return collected
            params["Marker"] = marker

    def _guarded(self, label: str, sink: _Sink, call: Callable[[], Any]) -> Any:
        """Run one API call; an expected failure degrades to UNAVAILABLE coverage.

        Unexpected errors propagate — this adapter never swallows what it
        does not recognize.
        """
        try:
            return call()
        except Exception as err:
            code = _expected_failure_code(err)
            if code is None:
                raise
            sink.coverage.append(self._unavailable(f"{label} could not be consulted ({code})"))
            return None

    def _canonical_role(self, role_arn: str, role_name: str) -> CanonicalId:
        """The role's ARN is authoritative; its name is the global-service fallback."""
        try:
            return parse_arn(role_arn)
        except IdParseError:
            return canonical_from_native("iam", "role", role_name)

    def _unavailable(self, reason: str) -> Coverage:
        return Coverage(
            source=EvidenceSource.IAM,
            status=CoverageStatus.UNAVAILABLE,
            reason=(
                f"{reason}; unavailable is a property of this source, "
                "never a conclusion of 'no dependency'"
            ),
            region=self._region,
        )
