"""Read-only CloudTrail evidence adapter.

Two input modes, one parser:

- **File mode** — ``parse_file``/``parse_document`` read a local
  LookupEvents-shaped JSON document (fixture events or an export), fully
  deterministic and offline.
- **Client mode** — ``collect`` with no path drives an injected CloudTrail
  client through ``lookup_events`` with an explicitly bounded, validated
  window (timezone-aware, ordered, at most 90 days — LookupEvents' own
  horizon) and NextToken pagination. :data:`ALLOWED_OPERATIONS` is the
  complete set of operations ever invoked; boto3 stays an optional extra,
  imported lazily inside the default client factory.

Semantics frozen by the build brief:

- LookupEvents exposes **management-plane events only**; the adapter never
  claims data-plane visibility, and every coverage record and every linked
  evidence explanation says so.
- A relationship candidate is emitted **only when both a source identity and
  a target resolve** to canonical IDs. Every other event is retained as
  unlinked evidence whose explanation says exactly why it could not be
  linked — retained, never dropped.
- Missing events are never negative evidence: an empty lookup is recorded
  with the caveat that a missing trail, a trail that does not cover the
  window, and genuinely no activity all look identical.
- Assumed-role session principals are normalized to the role they were
  assumed from, so observed usage joins the role the IAM adapter reports.
- This adapter emits evidence and relationship candidates only; it never
  invents ``Resource`` records — resources come from the resource adapters.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
)
from reality.domain.ids import CanonicalId, IdParseError, parse_arn
from reality.domain.models import Coverage, Evidence, Relationship

#: The complete set of operations this adapter may invoke — read-only lookup
#: only, never anything that mutates.
ALLOWED_OPERATIONS: frozenset[str] = frozenset({"lookup_events"})

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

#: Page size for lookup_events (the API's documented maximum).
LOOKUP_MAX_RESULTS = 50

#: LookupEvents cannot return events older than 90 days; windows longer than
#: that are refused rather than silently returning a partial history.
MAX_LOOKUP_WINDOW = timedelta(days=90)

#: Recorded with every coverage note and linked-evidence explanation.
DATA_PLANE_CAVEAT = (
    "LookupEvents exposes management-plane events only, within the most recent 90 days; "
    "data-plane usage is not visible, and absence of events is never evidence of absence"
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


def _parse_embedded(raw: Any) -> dict[str, Any] | None:
    """Decode the CloudTrailEvent JSON string; ``None`` when malformed."""
    if isinstance(raw, dict):  # already-decoded documents are accepted too
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _event_time(value: Any, fallback: datetime) -> datetime:
    """The event's time, or the scan timestamp when the record carries none."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for candidate in (value, value.replace("Z", "+00:00")):
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                continue
    return fallback


def _role_arn(principal_arn: str) -> str:
    """Map an assumed-role session principal to the role it was assumed from.

    CloudTrail reports session principals as
    ``arn:PARTITION:sts::account:assumed-role/role-name/session-name``; the
    durable identity — and the one the IAM adapter emits — is the role. The
    rebuilt ARN still goes through :func:`parse_arn`; no canonical key is
    ever constructed here.
    """
    parts = principal_arn.split(":", 5)
    if len(parts) != 6 or parts[2] != "sts":
        return principal_arn
    base, _, session = parts[5].rpartition("/")
    if not base.startswith("assumed-role/") or not session:
        return principal_arn
    return f"arn:{parts[1]}:iam::{parts[4]}:role/{base[len('assumed-role/') :]}"


def _actor(
    raw: dict[str, Any], embedded: dict[str, Any] | None
) -> tuple[str | None, CanonicalId | None, str | None]:
    """Resolve the acting identity: (raw ref, canonical ID, why-unresolved).

    Only a principal ARN inside the embedded event resolves; a bare
    ``Username`` is preserved as the raw ref but never guessed into a
    canonical identity.
    """
    if embedded is not None:
        identity = embedded.get("userIdentity")
        if isinstance(identity, dict):
            arn = identity.get("arn")
            if isinstance(arn, str) and arn.strip():
                try:
                    return arn, parse_arn(_role_arn(arn)), None
                except IdParseError:
                    return arn, None, f"the principal ARN {arn!r} cannot be normalized"
    username = raw.get("Username")
    if isinstance(username, str) and username.strip():
        detail = (
            "the embedded event JSON is malformed"
            if embedded is None
            else "the event carries no principal ARN"
        )
        return (
            username,
            None,
            f"{detail}, so the actor {username!r} cannot be resolved to a canonical identity",
        )
    return None, None, "the event carries no actor identity at all"


def _targets(raw: dict[str, Any]) -> list[tuple[str, CanonicalId | None, str | None]]:
    """Explicit resource targets: (raw ref, canonical ID, why-unresolvable).

    Only the event's ``Resources`` array is consulted — targets the source
    explicitly recorded, never values inferred from request parameters.
    """
    resources = raw.get("Resources")
    if not isinstance(resources, list):
        return []
    out: list[tuple[str, CanonicalId | None, str | None]] = []
    seen: set[str] = set()
    for entry in resources:
        if not isinstance(entry, dict):
            continue
        name = entry.get("ResourceName")
        if not isinstance(name, str) or not name.strip() or name in seen:
            continue
        seen.add(name)
        try:
            out.append((name, parse_arn(name), None))
        except IdParseError:
            if "*" in name or "?" in name:
                reason = "is a pattern, not a specific resource"
            elif "${" in name:
                reason = "contains policy variables"
            else:
                reason = "is not a normalizable ARN"
            out.append((name, None, reason))
    return out


def _document_events(document: Any) -> list[Any] | None:
    """Event list from a LookupEvents response, a pages array, or a bare list."""
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        pages = document.get("pages")
        if isinstance(pages, list):
            events: list[Any] = []
            for page in pages:
                if isinstance(page, dict):
                    events.extend(page.get("Events") or [])
            return events
        events_field = document.get("Events")
        if isinstance(events_field, list):
            return events_field
    return None


class CloudTrailAdapter(Adapter):
    """Read-only CloudTrail evidence collector with two input modes."""

    name = "cloudtrail"

    def __init__(
        self,
        *,
        profile: str | None = None,
        region: str | None = None,
        client_factory: ClientFactory | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> None:
        """Offline when given nothing; client mode when given anything.

        Any client-mode argument requires the complete explicit set — an
        opt-in profile, a region, and a bounded window — before any client
        can be constructed. The window is validated the same way for
        everyone: timezone-aware, ordered, and no longer than LookupEvents'
        own 90-day horizon.
        """
        if all(value is None for value in (profile, region, client_factory, start, end)):
            self._profile: str | None = None
            self._region: str | None = None
            self._client_factory: ClientFactory | None = None
            self._start: datetime | None = None
            self._end: datetime | None = None
            return
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
        if start is None or end is None:
            raise ConfigError(
                "a bounded lookup window (start and end) is required; "
                "unbounded CloudTrail lookups are refused"
            )
        if start.tzinfo is None or end.tzinfo is None:
            raise ConfigError("the lookup window bounds must be timezone-aware datetimes")
        if end <= start:
            raise ConfigError(
                f"the lookup window is inverted: start {start.isoformat()} "
                f"is not before end {end.isoformat()}"
            )
        if end - start > MAX_LOOKUP_WINDOW:
            raise ConfigError(
                f"the lookup window spans {end - start}, longer than the 90 days "
                "LookupEvents can return; split the scan into smaller windows"
            )
        self._profile = profile
        self._region = region
        self._client_factory = client_factory or _default_client_factory(profile, region)
        self._start = start
        self._end = end

    @classmethod
    def from_config(
        cls,
        config: RealityConfig,
        client_factory: ClientFactory | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CloudTrailAdapter:
        """Build the adapter behind the Prompt 1 opt-in configuration."""
        config.require_aws()
        profile = config.aws_profile
        region = config.aws_region
        if profile is None or region is None:  # pragma: no cover - require_aws rejects this
            raise ConfigError("require_aws() must run before building the adapter")
        return cls(
            profile=profile,
            region=region,
            client_factory=client_factory,
            start=start,
            end=end,
        )

    # --- entry point --------------------------------------------------------

    def collect(self, path: Path | str | None = None) -> AdapterResult:
        """Parse a local events file, or drive the opted-in client lookup."""
        if path is not None:
            return self.parse_file(Path(path))
        if self._client_factory is None:
            raise ConfigError(
                "no lookup client is configured: pass a local events file, or construct "
                "the adapter with an opted-in profile, region, and bounded window"
            )
        return self._collect_from_client()

    # --- file mode ------------------------------------------------------------

    def parse_file(self, path: Path) -> AdapterResult:
        """Parse a local LookupEvents-shaped JSON file, offline and read-only."""
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except OSError:
            return self._unavailable_result(f"could not read {path}")
        except json.JSONDecodeError as err:
            return self._unavailable_result(f"{path} is not valid JSON ({err.msg})")
        try:
            return self.parse_document(document, source_path=str(path))
        except AdapterError as err:
            return self._unavailable_result(f"{path}: {err.message}")

    def parse_document(self, document: Any, *, source_path: str | None = None) -> AdapterResult:
        """Parse a LookupEvents response, a pages array, or a bare event list."""
        events = _document_events(document)
        if events is None:
            raise AdapterError(
                "document is not a CloudTrail LookupEvents result "
                "(expected 'Events', 'pages', or a bare event list)",
                "$",
            )
        origin = source_path or "the supplied document"
        return self._parse_events(
            events,
            observed_at=datetime.now(UTC),
            locator_prefix=source_path or "cloudtrail:document",
            summary=f"{len(events)} event(s) parsed from {origin}",
        )

    # --- client mode ------------------------------------------------------------

    def _collect_from_client(self) -> AdapterResult:
        assert self._client_factory is not None and self._profile is not None
        assert self._region is not None and self._start is not None and self._end is not None
        client = self._client_factory("cloudtrail")
        params: dict[str, Any] = {
            "StartTime": self._start,
            "EndTime": self._end,
            "MaxResults": LOOKUP_MAX_RESULTS,
        }
        events: list[Any] = []
        try:
            while True:
                page = client.lookup_events(**params)
                events.extend(page.get("Events") or [])
                token = page.get("NextToken")
                if not token:
                    break
                # a fresh dict per page: the client never sees a mutated shared one
                params = {**params, "NextToken": token}
        except Exception as err:
            code = _expected_failure_code(err)
            if code is None:
                raise
            # The failed lookup contributes nothing — partial pages are
            # discarded so incomplete history cannot look complete.
            return self._unavailable_result(
                f"cloudtrail lookup_events could not be consulted ({code})"
            )
        summary = (
            f"cloudtrail lookup_events: {len(events)} management-plane event(s) within the "
            f"bounded window {self._start.isoformat()} .. {self._end.isoformat()} "
            f"(profile {self._profile!r}, region {self._region!r})"
        )
        if not events:
            summary += (
                "; no events matched — a missing trail, a trail that does not cover the "
                "window, and genuinely no activity all look identical"
            )
        return self._parse_events(
            events,
            observed_at=datetime.now(UTC),
            locator_prefix="cloudtrail:LookupEvents",
            summary=summary,
        )

    # --- shared parser ------------------------------------------------------------

    def _parse_events(
        self,
        events: list[Any],
        *,
        observed_at: datetime,
        locator_prefix: str,
        summary: str,
    ) -> AdapterResult:
        evidence: list[Evidence] = []
        coverage: list[Coverage] = []
        linked: dict[tuple[str, str], list[str]] = {}
        malformed_records = 0
        malformed_embedded = 0

        for index, raw in enumerate(events):
            if not isinstance(raw, dict):
                malformed_records += 1
                continue
            locator = f"{locator_prefix}#Events[{index}]"
            event_id = raw.get("EventId")
            if not isinstance(event_id, str) or not event_id.strip():
                event_id = f"index-{index}"
            event_name = _name(raw.get("EventName"), "(unknown event)") or "(unknown event)"
            event_source = _name(raw.get("EventSource"), None)
            where = f"{event_name} ({event_source})" if event_source else event_name
            event_time = _event_time(raw.get("EventTime"), observed_at)
            raw_embedded = raw.get("CloudTrailEvent")
            embedded = _parse_embedded(raw_embedded)
            if embedded is None and raw_embedded is not None:
                malformed_embedded += 1
            actor_ref, actor_id, actor_reason = _actor(raw, embedded)
            targets = _targets(raw)

            if actor_id is not None:
                assert actor_ref is not None
                for target_ref, target_id, reason in targets:
                    if target_id is not None:
                        self._link(
                            event_id=event_id,
                            where=where,
                            actor_ref=actor_ref,
                            actor_id=actor_id,
                            target_ref=target_ref,
                            target_id=target_id,
                            event_time=event_time,
                            locator=locator,
                            evidence=evidence,
                            linked=linked,
                        )
                    else:
                        assert reason is not None
                        evidence.append(
                            Evidence(
                                id=f"cloudtrail:{event_id}:{actor_ref}:{target_ref}",
                                source=EvidenceSource.CLOUDTRAIL,
                                type=EvidenceType.API_EVENT,
                                observed_at=event_time,
                                actor=actor_ref,
                                source_ref=actor_ref,
                                target_ref=target_ref,
                                source_canonical_id=actor_id.key,
                                strength=EvidenceStrength.LOW,
                                raw_locator=locator,
                                explanation=(
                                    f"CloudTrail event {where} by {actor_ref} names target "
                                    f"{target_ref!r}, but it {reason}; no relationship is "
                                    "emitted and the event is retained unlinked"
                                ),
                            )
                        )
                if not targets:
                    evidence.append(
                        Evidence(
                            id=f"cloudtrail:{event_id}:{actor_ref}:no-target",
                            source=EvidenceSource.CLOUDTRAIL,
                            type=EvidenceType.API_EVENT,
                            observed_at=event_time,
                            actor=actor_ref,
                            source_ref=actor_ref,
                            target_ref="(no explicit target)",
                            source_canonical_id=actor_id.key,
                            strength=EvidenceStrength.LOW,
                            raw_locator=locator,
                            explanation=(
                                f"CloudTrail event {where} by {actor_ref} names no explicit "
                                "resource target; it cannot support a relationship and is "
                                "retained unlinked"
                            ),
                        )
                    )
            else:
                assert actor_reason is not None
                ref = actor_ref or "(no actor)"
                strength = EvidenceStrength.UNKNOWN if embedded is None else EvidenceStrength.LOW
                if targets:
                    for target_ref, target_id, _reason in targets:
                        evidence.append(
                            Evidence(
                                id=f"cloudtrail:{event_id}:{ref}:{target_ref}",
                                source=EvidenceSource.CLOUDTRAIL,
                                type=EvidenceType.API_EVENT,
                                observed_at=event_time,
                                actor=actor_ref,
                                source_ref=ref,
                                target_ref=target_ref,
                                target_canonical_id=target_id.key if target_id else None,
                                strength=strength,
                                raw_locator=locator,
                                explanation=(
                                    f"CloudTrail event {where} on {target_ref!r}: "
                                    f"{actor_reason}; no relationship is emitted and the "
                                    "event is retained unlinked"
                                ),
                            )
                        )
                else:
                    evidence.append(
                        Evidence(
                            id=f"cloudtrail:{event_id}:{ref}:no-target",
                            source=EvidenceSource.CLOUDTRAIL,
                            type=EvidenceType.API_EVENT,
                            observed_at=event_time,
                            actor=actor_ref,
                            source_ref=ref,
                            target_ref="(no explicit target)",
                            strength=strength,
                            raw_locator=locator,
                            explanation=(
                                f"CloudTrail event {where}: {actor_reason} and the event "
                                "names no explicit resource target; retained unlinked"
                            ),
                        )
                    )

        relationships = [
            Relationship(
                source_canonical_id=source_key,
                target_canonical_id=target_key,
                type=RelationshipType.DEPENDS_ON,
                origin=RelationshipOrigin.CLOUDTRAIL,
                evidence_ids=tuple(evidence_ids),
            )
            for (source_key, target_key), evidence_ids in sorted(linked.items())
        ]
        if malformed_records:
            coverage.append(
                self._unavailable(
                    f"{malformed_records} malformed event record(s) skipped; "
                    "no relationship invented for them"
                )
            )
        if malformed_embedded:
            coverage.append(
                self._unavailable(
                    f"{malformed_embedded} event(s) carry malformed embedded CloudTrailEvent "
                    "JSON; each is retained as unlinked evidence with the actor unresolved, "
                    "and no relationship is invented for it"
                )
            )
        coverage.append(
            Coverage(
                source=EvidenceSource.CLOUDTRAIL,
                status=CoverageStatus.AVAILABLE,
                reason=f"{summary}; {DATA_PLANE_CAVEAT}",
                region=self._region,
            )
        )
        return AdapterResult(
            relationships=tuple(relationships),
            evidence=tuple(evidence),
            coverage=tuple(coverage),
        )

    def _link(
        self,
        *,
        event_id: str,
        where: str,
        actor_ref: str,
        actor_id: CanonicalId,
        target_ref: str,
        target_id: CanonicalId,
        event_time: datetime,
        locator: str,
        evidence: list[Evidence],
        linked: dict[tuple[str, str], list[str]],
    ) -> None:
        """Record one observed usage pair: HIGH evidence plus a candidate."""
        evidence_id = f"cloudtrail:{event_id}:{actor_ref}:{target_ref}"
        evidence.append(
            Evidence(
                id=evidence_id,
                source=EvidenceSource.CLOUDTRAIL,
                type=EvidenceType.API_EVENT,
                observed_at=event_time,
                actor=actor_ref,
                source_ref=actor_ref,
                target_ref=target_ref,
                source_canonical_id=actor_id.key,
                target_canonical_id=target_id.key,
                strength=EvidenceStrength.HIGH,
                raw_locator=locator,
                explanation=(
                    f"CloudTrail event {where} by {actor_ref} on {target_ref}: observed "
                    "management-plane usage; data-plane usage is not claimed"
                ),
            )
        )
        linked.setdefault((actor_id.key, target_id.key), []).append(evidence_id)

    # --- helpers ------------------------------------------------------------

    def _unavailable(self, reason: str) -> Coverage:
        return Coverage(
            source=EvidenceSource.CLOUDTRAIL,
            status=CoverageStatus.UNAVAILABLE,
            reason=(
                f"{reason}; unavailable is a property of this source, "
                "never a conclusion of 'no dependency'"
            ),
            region=self._region,
        )

    def _unavailable_result(self, reason: str) -> AdapterResult:
        return AdapterResult(coverage=(self._unavailable(reason),))


def _name(value: Any, fallback: str | None) -> str | None:
    """A non-empty string field, or the fallback when absent/malformed."""
    if isinstance(value, str) and value.strip():
        return value
    return fallback
