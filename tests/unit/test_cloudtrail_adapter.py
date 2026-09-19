"""Tests for the read-only CloudTrail evidence adapter.

File mode runs fully offline against local JSON fixtures. Client mode runs
against fake injected clients (plus, when the optional aws extra is
installed, one botocore Stubber case). No test needs credentials, a profile,
or network access, and none can mutate anything: the fake client refuses
every operation outside the read-only lookup whitelist. The central property
under test: a valid event becomes observed evidence, and every other case —
no target, unresolvable actor, malformed JSON — stays unlinked/unknown
rather than absent.
"""

from __future__ import annotations

import ast
import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from reality.adapters.base import AdapterError
from reality.adapters.cloudtrail import ALLOWED_OPERATIONS, CloudTrailAdapter
from reality.config import ConfigError, RealityConfig
from reality.domain.enums import (
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cloudtrail"

PROFILE = "sandbox"
REGION = "eu-west-1"
START = datetime(2026, 3, 1, 0, 0, tzinfo=UTC)
END = datetime(2026, 3, 2, 0, 0, tzinfo=UTC)

# The assumed-role session principal resolves to the same canonical role the
# IAM adapter emits, which is what makes observed usage join declared policy.
PROCESSOR_ROLE = "aws/iam/role/-/123456789012/processor_role"
SESSION_PRINCIPAL = "arn:aws:sts::123456789012:assumed-role/processor_role/session-1"
DATA_LAKE = "aws/s3/bucket/-/-/data-lake"
NEW_BUCKET = "aws/s3/bucket/-/-/new-bucket"


# --- fakes: scripted clients, no boto3 required ------------------------------


class FakeClientError(Exception):
    """Mimics ``botocore.exceptions.ClientError``'s ``.response`` shape."""

    def __init__(self, code: str, message: str = "simulated failure") -> None:
        super().__init__(f"{code}: {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeClient:
    """A scripted boto3 client that records calls and refuses mutations."""

    def __init__(self, service: str, script: dict[str, list[Any]]) -> None:
        self.service = service
        self._script = script
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str) -> Any:
        if operation.startswith("_"):
            raise AttributeError(operation)

        def _call(**kwargs: Any) -> Any:
            if operation not in ALLOWED_OPERATIONS:
                raise AssertionError(
                    f"{self.service}.{operation} is not an allowed read-only operation"
                )
            self.calls.append((operation, dict(kwargs)))  # a copy: callers may reuse dicts
            queue = self._script[operation]
            if not queue:
                raise AssertionError(f"{self.service}.{operation} called more times than scripted")
            outcome = queue.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return _call


class FakeClientFactory:
    """A client factory that hands out one recorded fake per service."""

    def __init__(self, script: dict[str, dict[str, list[Any]]]) -> None:
        self._script = script
        self.clients: dict[str, FakeClient] = {}

    def __call__(self, service: str) -> FakeClient:
        if service not in self.clients:
            self.clients[service] = FakeClient(service, self._script.get(service, {}))
        return self.clients[service]


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def full_script() -> dict[str, dict[str, list[Any]]]:
    return {"cloudtrail": {"lookup_events": list(load("lookup_events.json")["pages"])}}


def offline_adapter() -> CloudTrailAdapter:
    return CloudTrailAdapter()


def make_client_adapter(
    script: dict[str, dict[str, list[Any]]] | None = None,
) -> tuple[CloudTrailAdapter, FakeClientFactory]:
    factory = FakeClientFactory(script if script is not None else full_script())
    adapter = CloudTrailAdapter(
        profile=PROFILE, region=REGION, client_factory=factory, start=START, end=END
    )
    return adapter, factory


def parse_fixture() -> Any:
    return offline_adapter().parse_file(FIXTURES / "events.json")


def evidence_by_id(result: Any) -> dict[str, Any]:
    by_id = {item.id: item for item in result.evidence}
    assert len(by_id) == len(result.evidence)  # IDs are unique
    return by_id


# --- configuration and window gate ---------------------------------------------


def test_offline_instance_needs_nothing() -> None:
    adapter = offline_adapter()
    assert adapter.name == "cloudtrail"
    result = adapter.parse_file(FIXTURES / "events.json")
    assert result.evidence  # file mode works with no profile, region, or client


def test_client_mode_requires_an_explicit_profile() -> None:
    with pytest.raises(ConfigError, match="profile"):
        CloudTrailAdapter(region=REGION, start=START, end=END)


def test_client_mode_requires_an_explicit_region() -> None:
    with pytest.raises(ConfigError, match="region"):
        CloudTrailAdapter(profile=PROFILE, start=START, end=END)


def test_client_mode_requires_a_bounded_window() -> None:
    with pytest.raises(ConfigError, match="bounded lookup window"):
        CloudTrailAdapter(profile=PROFILE, region=REGION)


def test_window_must_be_ordered() -> None:
    with pytest.raises(ConfigError, match="inverted"):
        CloudTrailAdapter(profile=PROFILE, region=REGION, start=END, end=START)


def test_window_is_capped_at_the_lookup_horizon() -> None:
    with pytest.raises(ConfigError, match="90 days"):
        CloudTrailAdapter(
            profile=PROFILE,
            region=REGION,
            start=START,
            end=START + timedelta(days=91),
        )


def test_window_must_be_timezone_aware() -> None:
    naive_start = datetime(2026, 3, 1, 0, 0)
    naive_end = datetime(2026, 3, 2, 0, 0)
    with pytest.raises(ConfigError, match="timezone-aware"):
        CloudTrailAdapter(profile=PROFILE, region=REGION, start=naive_start, end=naive_end)


def test_from_config_requires_the_explicit_opt_in_triple() -> None:
    config = RealityConfig(aws_opt_in=False, aws_profile=PROFILE, aws_region=REGION)
    with pytest.raises(ConfigError):
        CloudTrailAdapter.from_config(config, start=START, end=END)


def test_from_config_builds_an_adapter_with_the_window() -> None:
    config = RealityConfig(aws_opt_in=True, aws_profile=PROFILE, aws_region=REGION)
    adapter = CloudTrailAdapter.from_config(
        config, client_factory=FakeClientFactory(full_script()), start=START, end=END
    )
    assert adapter.name == "cloudtrail"
    assert adapter.collect().evidence  # the injected factory means no boto3 is needed


# --- safety: allowed operations only -------------------------------------------


def test_every_invoked_operation_is_in_the_read_only_whitelist() -> None:
    adapter, factory = make_client_adapter()
    adapter.collect()
    invoked = {op for client in factory.clients.values() for op, _ in client.calls}
    assert invoked == ALLOWED_OPERATIONS == {"lookup_events"}


MUTATING_PREFIXES = (
    "create_",
    "delete_",
    "put_",
    "update_",
    "modify_",
    "terminate_",
    "attach_",
    "detach_",
    "authorize_",
    "revoke_",
    "run_",
    "start_",
    "stop_",
    "add_",
    "remove_",
    "set_",
    "register_",
    "enable_",
    "upload_",
    "tag_",
    "untag_",
    "simulate_",
)


def test_adapter_source_never_calls_mutating_operations() -> None:
    from reality.adapters import cloudtrail as module

    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = node.func
            name = getattr(called, "attr", None) or getattr(called, "id", None)
            assert name is None or not name.startswith(MUTATING_PREFIXES), (
                f"adapter must not call {name!r}"
            )


def test_boto3_is_imported_lazily_not_at_module_level() -> None:
    from reality.adapters import cloudtrail as module

    tree = ast.parse(inspect.getsource(module))
    boto_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Import) and any(alias.name == "boto3" for alias in node.names)
    ]
    assert boto_imports, "the default client factory must import boto3 somewhere"
    assert all(node.col_offset > 0 for node in boto_imports)  # nested in a function body


# --- file mode: parsing forms -----------------------------------------------------


def test_resolvable_event_produces_observed_evidence_and_relationship() -> None:
    result = parse_fixture()
    assert len(result.relationships) == 1
    rel = result.relationships[0]
    assert rel.source_canonical_id == PROCESSOR_ROLE
    assert rel.target_canonical_id == DATA_LAKE
    assert rel.type == RelationshipType.DEPENDS_ON
    assert rel.origin == RelationshipOrigin.CLOUDTRAIL
    assert rel.evidence_ids
    evidence = evidence_by_id(result)[rel.evidence_ids[0]]
    assert evidence.source == EvidenceSource.CLOUDTRAIL
    assert evidence.type == EvidenceType.API_EVENT
    assert evidence.strength == EvidenceStrength.HIGH  # the usage actually happened
    assert evidence.observed_at == datetime(2026, 3, 1, 10, 15, tzinfo=UTC)
    assert evidence.raw_locator.endswith("#Events[0]")
    assert evidence.explanation


def test_assumed_role_principal_is_normalized_to_the_role() -> None:
    result = parse_fixture()
    evidence = next(
        item for item in result.evidence if item.id.startswith("cloudtrail:ct-0001-resolvable:")
    )
    # The session principal resolves to the role identity, so observed usage
    # joins the role the IAM adapter reports.
    assert evidence.source_canonical_id == PROCESSOR_ROLE
    assert evidence.actor == SESSION_PRINCIPAL  # the raw principal is preserved
    assert evidence.source_ref == SESSION_PRINCIPAL


def test_event_with_no_target_is_retained_unlinked() -> None:
    result = parse_fixture()
    unlinked = next(
        item
        for item in result.evidence
        if item.id.startswith("cloudtrail:ct-0002-no-target:")
        and item.target_ref == "(no explicit target)"
    )
    assert unlinked.strength == EvidenceStrength.LOW
    assert unlinked.target_ref == "(no explicit target)"
    assert "names no explicit resource target" in unlinked.explanation
    assert unlinked.source_canonical_id == PROCESSOR_ROLE
    # retained, not absent — and it backs no relationship
    assert not any(unlinked.id in rel.evidence_ids for rel in result.relationships)


def test_malformed_embedded_json_is_unlinked_and_recorded() -> None:
    result = parse_fixture()
    record = next(
        r
        for r in result.coverage
        if r.status == CoverageStatus.UNAVAILABLE and "malformed embedded" in r.reason
    )
    assert "1 event(s)" in record.reason
    evidence = next(
        item for item in result.evidence if item.id.startswith("cloudtrail:ct-0003-malformed:")
    )
    assert evidence.strength == EvidenceStrength.UNKNOWN
    assert evidence.source_canonical_id is None  # the actor could not be resolved
    assert evidence.target_canonical_id == NEW_BUCKET  # the explicit target still is
    assert "malformed" in evidence.explanation
    assert not any(evidence.id in rel.evidence_ids for rel in result.relationships)


def test_unresolvable_target_is_retained_unlinked() -> None:
    result = parse_fixture()
    evidence = next(
        item
        for item in result.evidence
        if item.id.startswith("cloudtrail:ct-0004-unresolvable-target:")
    )
    assert evidence.strength == EvidenceStrength.LOW
    assert evidence.source_canonical_id == PROCESSOR_ROLE
    assert evidence.target_ref == "i-0notanarn"
    assert "not a normalizable ARN" in evidence.explanation
    assert not any(evidence.id in rel.evidence_ids for rel in result.relationships)


def test_file_mode_counts_are_exact() -> None:
    result = parse_fixture()
    assert len(result.evidence) == 4
    assert len(result.relationships) == 1
    assert len(result.coverage) == 2  # available summary + malformed-embedded record
    assert result.resources == ()  # evidence only; resources come from other adapters


def test_data_plane_caveat_is_recorded() -> None:
    result = parse_fixture()
    available = next(r for r in result.coverage if r.status == CoverageStatus.AVAILABLE)
    assert "management-plane events only" in available.reason
    assert "data-plane usage is not visible" in available.reason
    linked = next(item for item in result.evidence if item.strength == EvidenceStrength.HIGH)
    assert "data-plane usage is not claimed" in linked.explanation


def test_missing_events_are_never_negative_evidence() -> None:
    result = offline_adapter().parse_document({"Events": []})
    assert result.evidence == ()
    assert result.relationships == ()
    available = next(r for r in result.coverage if r.status == CoverageStatus.AVAILABLE)
    assert "0 event(s)" in available.reason
    assert "never evidence of absence" in available.reason


def test_pages_document_and_bare_list_are_accepted() -> None:
    adapter = offline_adapter()
    via_pages = adapter.parse_document(load("lookup_events.json"))
    assert len(via_pages.evidence) == 2
    via_list = adapter.parse_document(load("events.json")["Events"])
    assert len(via_list.evidence) == 4


def test_unrecognized_document_shape_is_rejected() -> None:
    with pytest.raises(AdapterError) as exc_info:
        offline_adapter().parse_document({"unexpected": "shape"})
    assert exc_info.value.json_path == "$"


def test_parse_file_reports_unreadable_file(tmp_path: Path) -> None:
    result = offline_adapter().parse_file(tmp_path / "does-not-exist.json")
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "could not read" in result.coverage[0].reason


def test_parse_file_reports_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    result = offline_adapter().parse_file(bad)
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "not valid JSON" in result.coverage[0].reason


def test_evidence_ids_are_deterministic() -> None:
    first = parse_fixture()
    second = parse_fixture()
    assert {item.id for item in first.evidence} == {item.id for item in second.evidence}


def test_multiple_events_for_one_pair_aggregate_into_one_relationship() -> None:
    events = load("events.json")["Events"]
    document = {"Events": [events[0], dict(events[0], EventId="ct-0001-again")]}
    result = offline_adapter().parse_document(document)
    assert len(result.relationships) == 1
    assert len(result.relationships[0].evidence_ids) == 2


# --- client mode ---------------------------------------------------------------


def test_lookup_sends_the_bounded_window_and_paginates() -> None:
    adapter, factory = make_client_adapter()
    result = adapter.collect()
    assert len(result.evidence) == 2  # both pages collected
    calls = [kwargs for _, kwargs in factory.clients["cloudtrail"].calls]
    assert calls == [
        {"StartTime": START, "EndTime": END, "MaxResults": 50},
        {"StartTime": START, "EndTime": END, "MaxResults": 50, "NextToken": "ct-page-2"},
    ]


def test_client_coverage_records_the_window_and_scan_context() -> None:
    result = make_client_adapter()[0].collect()
    available = next(r for r in result.coverage if r.status == CoverageStatus.AVAILABLE)
    assert available.source == EvidenceSource.CLOUDTRAIL
    assert available.region == REGION
    assert "bounded window" in available.reason
    assert START.isoformat() in available.reason
    assert END.isoformat() in available.reason
    assert PROFILE in available.reason


def test_empty_lookup_records_the_missing_trail_ambiguity() -> None:
    script = {"cloudtrail": {"lookup_events": [load("lookup_events_empty.json")]}}
    adapter, _ = make_client_adapter(script)
    result = adapter.collect()
    assert result.evidence == ()
    available = next(r for r in result.coverage if r.status == CoverageStatus.AVAILABLE)
    assert "no events matched" in available.reason
    assert "missing trail" in available.reason
    assert "never evidence of absence" in available.reason


def test_access_denied_degrades_to_unavailable_coverage() -> None:
    script = {"cloudtrail": {"lookup_events": [FakeClientError("AccessDenied")]}}
    adapter, _ = make_client_adapter(script)
    result = adapter.collect()
    assert len(result.coverage) == 1
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "AccessDenied" in result.coverage[0].reason
    assert result.evidence == ()
    assert result.relationships == ()


def test_throttling_mid_pagination_discards_partial_results() -> None:
    pages = list(load("lookup_events.json")["pages"])
    script = {"cloudtrail": {"lookup_events": [pages[0], FakeClientError("Throttling")]}}
    adapter, _ = make_client_adapter(script)
    result = adapter.collect()
    assert result.evidence == ()  # page 1's partials must not look complete
    assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
    assert "Throttling" in result.coverage[0].reason


def test_unexpected_client_error_code_propagates() -> None:
    script = {"cloudtrail": {"lookup_events": [FakeClientError("InvalidParameterException")]}}
    adapter, _ = make_client_adapter(script)
    with pytest.raises(FakeClientError):
        adapter.collect()


def test_non_client_error_propagates() -> None:
    script = {"cloudtrail": {"lookup_events": [ValueError("boom")]}}
    adapter, _ = make_client_adapter(script)
    with pytest.raises(ValueError, match="boom"):
        adapter.collect()


def test_collect_without_path_or_client_is_refused() -> None:
    with pytest.raises(ConfigError, match="no lookup client is configured"):
        offline_adapter().collect()


def test_collect_accepts_a_path_in_file_mode() -> None:
    result = offline_adapter().collect(FIXTURES / "events.json")
    assert len(result.evidence) == 4


# --- optional: real botocore Stubber, only when the aws extra is installed --------------------


class TestWithBotocoreStubber:
    def test_real_client_error_shape_is_classified(self) -> None:
        boto3 = pytest.importorskip("boto3")
        pytest.importorskip("botocore")
        from botocore.stub import Stubber

        client = boto3.client(
            "cloudtrail",
            region_name=REGION,
            aws_access_key_id="AKIAFAKEFAKEFAKEFAKE",  # never used: all calls are stubbed
            aws_secret_access_key="fixture-only-not-a-secret",
        )
        stubber = Stubber(client)
        # lookup_events is the first and only call: its failure ends the scan.
        stubber.add_client_error("lookup_events", service_error_code="AccessDenied")
        stubber.activate()

        class SingleClientFactory:
            def __call__(self, service: str) -> Any:
                assert service == "cloudtrail"
                return client

        adapter = CloudTrailAdapter(
            profile=PROFILE,
            region=REGION,
            client_factory=SingleClientFactory(),
            start=START,
            end=END,
        )
        result = adapter.collect()
        assert len(result.coverage) == 1
        assert result.coverage[0].status == CoverageStatus.UNAVAILABLE
        assert "AccessDenied" in result.coverage[0].reason
