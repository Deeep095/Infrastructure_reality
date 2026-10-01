"""Read-only Terraform JSON adapter.

Accepts local JSON documents that the *user* already produced with
``terraform show -json`` — a state document (``values.root_module``) or a
plan document (``resource_changes`` plus optional ``planned_values``). This
module never runs Terraform, never shells out, and never writes; a test
asserts the source contains no subprocess usage at all.

Vertical-slice scope (per the build brief): ``aws_instance``,
``aws_lambda_function``, ``aws_db_instance``, ``aws_s3_bucket``,
``aws_security_group``, ``aws_iam_role``, plus IAM role attachment
references (``aws_lambda_function.role``, ``aws_instance.iam_instance_profile``)
and explicit ``depends_on`` references. Declared resources are identified in
the Terraform namespace (their address is their canonical ID) with native
IDs and ARNs preserved alongside for later reconciliation; unknown or
deferred values ("(unknown)", "(known after apply)") are preserved as
UNKNOWN evidence, never guessed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reality.adapters.base import Adapter, AdapterError, AdapterResult
from reality.domain.enums import (
    ChangeAction,
    CoverageStatus,
    EvidenceSource,
    EvidenceStrength,
    EvidenceType,
    RelationshipOrigin,
    RelationshipType,
    ResourceType,
)
from reality.domain.ids import IdParseError, parse_arn, parse_terraform_address, unresolved
from reality.domain.models import Coverage, Evidence, Relationship, Resource, TerraformChange

#: Terraform resource types this slice understands; anything else is still
#: recorded as a declared resource of type TERRAFORM_RESOURCE.
SUPPORTED_TYPES: dict[str, ResourceType] = {
    "aws_instance": ResourceType.EC2_INSTANCE,
    "aws_lambda_function": ResourceType.LAMBDA_FUNCTION,
    "aws_db_instance": ResourceType.RDS_DB_INSTANCE,
    "aws_s3_bucket": ResourceType.S3_BUCKET,
    "aws_security_group": ResourceType.SECURITY_GROUP,
    "aws_iam_role": ResourceType.IAM_ROLE,
}

#: Markers Terraform uses for values that are not known at parse time.
UNKNOWN_MARKERS: frozenset[str] = frozenset({"(unknown)", "(known after apply)", "(sensitive)"})


def _is_unknown(value: Any) -> bool:
    return isinstance(value, str) and value.strip() in UNKNOWN_MARKERS


def _known(value: Any) -> str | None:
    """Pass through a value unless it is absent or an unknown marker."""
    if value is None or _is_unknown(value):
        return None
    return str(value)


def _require_str(container: dict[str, Any], key: str, path: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"'{key}' must be a non-empty string", f"{path}.{key}")
    return value


def _string_list(container: dict[str, Any], key: str, path: str) -> list[str]:
    value = container.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise AdapterError(f"'{key}' must be an array", f"{path}.{key}")
    return [str(item) for item in value]


class _DeclaredIndex:
    """Lookup from a declaration's references to its canonical ID."""

    def __init__(self, resources: list[Resource]) -> None:
        self.by_address: dict[str, str] = {}
        self.by_native: dict[str, str] = {}
        self.by_arn: dict[str, str] = {}
        for resource in resources:
            if resource.terraform_address:
                self.by_address.setdefault(resource.terraform_address, resource.canonical_id)
            if resource.native_id:
                self.by_native.setdefault(resource.native_id, resource.canonical_id)
            if resource.arn:
                self.by_arn.setdefault(resource.arn, resource.canonical_id)


class TerraformAdapter(Adapter):
    """Parses ``terraform show -json`` documents supplied by the caller."""

    name = "terraform"

    def collect(self, path: str | Path) -> AdapterResult:
        return self.parse_file(path)

    # --- entry points -------------------------------------------------------

    def parse_file(self, path: str | Path) -> AdapterResult:
        """Read a JSON file; on any rejection, return a safe coverage record.

        Schema errors surface as ``Coverage(UNAVAILABLE)`` with the JSON
        path in the reason — the caller never gets an exception from a bad
        file, only a report of what could not be parsed.
        """
        file_path = Path(path)
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as err:
            return self._rejected(
                EvidenceSource.TERRAFORM_STATE, f"could not read {file_path}: {err}"
            )
        try:
            document = json.loads(text)
        except json.JSONDecodeError as err:
            return self._rejected(
                EvidenceSource.TERRAFORM_STATE, f"invalid JSON in {file_path}: {err}"
            )
        try:
            return self.parse_document(document, source_path=str(file_path))
        except AdapterError as err:
            kind = (
                EvidenceSource.TERRAFORM_PLAN
                if isinstance(document, dict) and "resource_changes" in document
                else EvidenceSource.TERRAFORM_STATE
            )
            return self._rejected(kind, f"terraform input rejected: {err}")

    @staticmethod
    def _rejected(source: EvidenceSource, reason: str) -> AdapterResult:
        return AdapterResult(
            coverage=(Coverage(source=source, status=CoverageStatus.UNAVAILABLE, reason=reason),)
        )

    def parse_document(self, document: Any, source_path: str = "<document>") -> AdapterResult:
        """Parse an already-loaded document; dispatches state vs plan."""
        if not isinstance(document, dict):
            raise AdapterError("document must be a JSON object", "$")
        if "resource_changes" in document:
            return self._parse_plan(document, source_path)
        if "values" in document:
            return self._parse_state(document, source_path)
        raise AdapterError(
            "not a `terraform show -json` document: "
            "expected 'resource_changes' (plan) or 'values' (state)",
            "$",
        )

    # --- state ---------------------------------------------------------------

    def _parse_state(self, document: dict[str, Any], source_path: str) -> AdapterResult:
        values = document["values"]
        if values is None:
            return AdapterResult(
                coverage=(
                    Coverage(
                        source=EvidenceSource.TERRAFORM_STATE,
                        status=CoverageStatus.AVAILABLE,
                        reason=f"terraform state ({source_path}) has no values (empty state)",
                    ),
                )
            )
        if not isinstance(values, dict):
            raise AdapterError("'values' must be a JSON object or null", "$.values")
        root = values.get("root_module")
        if not isinstance(root, dict):
            raise AdapterError("'root_module' must be a JSON object", "$.values.root_module")
        resources, relationships, evidence, address_map, unsupported = self._collect_declared(
            root, "$.values.root_module", EvidenceSource.TERRAFORM_STATE, source_path
        )
        coverage = Coverage(
            source=EvidenceSource.TERRAFORM_STATE,
            status=CoverageStatus.AVAILABLE,
            reason=(
                f"parsed terraform state ({source_path}): {len(resources)} declared resources "
                f"({unsupported} unsupported type(s) recorded as terraform_resource), "
                f"{len(relationships)} relationship candidates"
            ),
        )
        return AdapterResult(
            resources=tuple(resources),
            relationships=tuple(relationships),
            evidence=tuple(evidence),
            coverage=(coverage,),
            address_map=address_map,
        )

    # --- plan ----------------------------------------------------------------

    def _parse_plan(self, document: dict[str, Any], source_path: str) -> AdapterResult:
        raw_changes = document.get("resource_changes")
        if not isinstance(raw_changes, list):
            raise AdapterError("'resource_changes' must be an array", "$.resource_changes")
        changes: list[TerraformChange] = []
        for index, raw in enumerate(raw_changes):
            path = f"$.resource_changes[{index}]"
            if not isinstance(raw, dict):
                raise AdapterError("resource change must be a JSON object", path)
            address = _require_str(raw, "address", path)
            tf_type = _require_str(raw, "type", path)
            change = raw.get("change")
            if not isinstance(change, dict):
                raise AdapterError("'change' must be a JSON object", f"{path}.change")
            actions = self._classify_actions(change, f"{path}.change")
            changes.append(
                TerraformChange(
                    address=address,
                    tf_resource_type=tf_type,
                    actions=actions,
                    canonical_id=self._address_key(address, path),
                )
            )

        resources: list[Resource] = []
        relationships: list[Relationship] = []
        evidence: list[Evidence] = []
        address_map: dict[str, str] = {}
        unsupported = 0
        planned = document.get("planned_values")
        if planned is not None:
            if not isinstance(planned, dict):
                raise AdapterError("'planned_values' must be a JSON object", "$.planned_values")
            root = planned.get("root_module")
            if not isinstance(root, dict):
                raise AdapterError(
                    "'root_module' must be a JSON object", "$.planned_values.root_module"
                )
            resources, relationships, evidence, address_map, unsupported = self._collect_declared(
                root, "$.planned_values.root_module", EvidenceSource.TERRAFORM_PLAN, source_path
            )
        coverage = Coverage(
            source=EvidenceSource.TERRAFORM_PLAN,
            status=CoverageStatus.AVAILABLE,
            reason=(
                f"parsed terraform plan ({source_path}): {len(changes)} changes, "
                f"{len(resources)} planned resources, {len(relationships)} relationship candidates"
            ),
        )
        return AdapterResult(
            resources=tuple(resources),
            relationships=tuple(relationships),
            evidence=tuple(evidence),
            coverage=(coverage,),
            terraform_changes=tuple(changes),
            address_map=address_map,
        )

    @staticmethod
    def _classify_actions(change: dict[str, Any], path: str) -> tuple[ChangeAction, ...]:
        """Map raw plan actions to ChangeActions; delete+create is REPLACE.

        Recognizing a replacement is classification, not action: nothing is
        applied, proposed, or executed here.
        """
        raw_actions = change.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions:
            raise AdapterError("'actions' must be a non-empty array", f"{path}.actions")
        mapped: list[ChangeAction] = []
        for index, action in enumerate(raw_actions):
            if action == "no-op":
                mapped.append(ChangeAction.NOOP)
            elif action in ("create", "read", "update", "delete"):
                mapped.append(ChangeAction(action))
            else:
                raise AdapterError(f"unrecognized action {action!r}", f"{path}.actions[{index}]")
        if ChangeAction.DELETE in mapped and ChangeAction.CREATE in mapped:
            return (ChangeAction.REPLACE,)
        return tuple(mapped)

    # --- shared declared-resource collection ---------------------------------

    def _collect_declared(
        self,
        root_module: dict[str, Any],
        root_path: str,
        source: EvidenceSource,
        source_path: str,
    ) -> tuple[list[Resource], list[Relationship], list[Evidence], dict[str, str], int]:
        raw_resources = self._walk_modules(root_module, root_path)
        resources: list[Resource] = []
        unsupported = 0
        for raw, path in raw_resources:
            if raw.get("mode", "managed") == "data":
                continue  # data sources are not managed cloud resources
            resource = self._build_resource(raw, path, source)
            if resource.resource_type == ResourceType.TERRAFORM_RESOURCE:
                unsupported += 1
            resources.append(resource)
        index = _DeclaredIndex(resources)
        relationships: list[Relationship] = []
        evidence: list[Evidence] = []
        for raw, path in raw_resources:
            if raw.get("mode", "managed") == "data":
                continue
            self._emit_links(raw, path, index, source, source_path, relationships, evidence)
        address_map = {
            address: self._canonical_id(resource)
            for resource in resources
            if (address := resource.terraform_address) is not None
        }
        return resources, relationships, evidence, address_map, unsupported

    def _walk_modules(self, module: dict[str, Any], path: str) -> list[tuple[dict[str, Any], str]]:
        """Collect (resource, json_path) pairs from a module tree recursively."""
        collected: list[tuple[dict[str, Any], str]] = []
        raw_resources = module.get("resources", [])
        if not isinstance(raw_resources, list):
            raise AdapterError("'resources' must be an array", f"{path}.resources")
        for index, raw in enumerate(raw_resources):
            resource_path = f"{path}.resources[{index}]"
            if not isinstance(raw, dict):
                raise AdapterError("resource entry must be a JSON object", resource_path)
            collected.append((raw, resource_path))
        children = module.get("child_modules", [])
        if not isinstance(children, list):
            raise AdapterError("'child_modules' must be an array", f"{path}.child_modules")
        for index, child in enumerate(children):
            child_path = f"{path}.child_modules[{index}]"
            if not isinstance(child, dict):
                raise AdapterError("child module must be a JSON object", child_path)
            collected.extend(self._walk_modules(child, child_path))
        return collected

    def _build_resource(self, raw: dict[str, Any], path: str, source: EvidenceSource) -> Resource:
        address = _require_str(raw, "address", path)
        tf_type = _require_str(raw, "type", path)
        values = raw.get("values")
        if values is None:
            values = {}
        elif not isinstance(values, dict):
            raise AdapterError("'values' must be a JSON object or null", f"{path}.values")
        return Resource(
            canonical_id=self._address_key(address, path),
            resource_type=SUPPORTED_TYPES.get(tf_type, ResourceType.TERRAFORM_RESOURCE),
            provider="terraform",
            native_id=_known(values.get("id")),
            arn=_known(values.get("arn")),
            terraform_address=address,
            name=_known(raw.get("name")),
            source=source,
        )

    @staticmethod
    def _address_key(address: str, path: str) -> str:
        try:
            return parse_terraform_address(address).key
        except IdParseError as err:
            raise AdapterError(f"invalid Terraform address: {err}", f"{path}.address") from err

    @staticmethod
    def _canonical_id(resource: Resource) -> str:
        """The address-key canonical ID; never ``None`` for a declared resource.

        ``_build_resource`` always sets ``canonical_id`` via ``_address_key``,
        so the Optional in the model is a database-read concern, not a
        declaration one. The check keeps the mapping's value type honest
        instead of widening it to ``str | None``.
        """
        if resource.canonical_id is None:  # pragma: no cover - see docstring
            raise AdapterError("declared resource has no canonical ID")
        return resource.canonical_id

    # --- declared relationship candidates ------------------------------------

    def _emit_links(
        self,
        raw: dict[str, Any],
        path: str,
        index: _DeclaredIndex,
        source: EvidenceSource,
        source_path: str,
        relationships: list[Relationship],
        evidence: list[Evidence],
    ) -> None:
        address = _require_str(raw, "address", path)
        tf_type = raw.get("type", "")
        values = raw.get("values") or {}
        if not isinstance(values, dict):
            raise AdapterError("'values' must be a JSON object or null", f"{path}.values")
        source_key = index.by_address.get(address)
        if source_key is None:
            return
        for ref, relationship_type, mode, attribute in self._link_specs(tf_type, values, raw, path):
            is_unknown = _is_unknown(ref)
            target_key = self._resolve(ref, mode, index)
            evidence_id = f"tf:{source.value}:{address}:{relationship_type.value}:{attribute}:{ref}"
            if is_unknown:
                strength = EvidenceStrength.UNKNOWN
                explanation = (
                    f"Terraform declares '{attribute}' on {address}, but its value is "
                    "unknown at parse time; the target is recorded unresolved, not guessed"
                )
            elif attribute == "depends_on":
                strength = EvidenceStrength.HIGH
                explanation = (
                    f"Terraform configuration declares an explicit depends_on "
                    f"from {address} to {ref}"
                )
            else:
                strength = EvidenceStrength.MEDIUM
                explanation = f"Terraform configuration sets '{attribute}' = {ref!r} on {address}"
            evidence.append(
                Evidence(
                    id=evidence_id,
                    source=source,
                    type=EvidenceType.CONFIG_REFERENCE,
                    observed_at=None,
                    actor="terraform",
                    source_ref=address,
                    target_ref=str(ref),
                    source_canonical_id=source_key,
                    target_canonical_id=target_key,
                    strength=strength,
                    raw_locator=f"{source_path}#{path}.{attribute}",
                    explanation=explanation,
                )
            )
            relationships.append(
                Relationship(
                    source_canonical_id=source_key,
                    target_canonical_id=target_key,
                    type=relationship_type,
                    origin=RelationshipOrigin.TERRAFORM_DECLARED,
                    evidence_ids=(evidence_id,),
                )
            )

    @staticmethod
    def _link_specs(
        tf_type: str, values: dict[str, Any], raw: dict[str, Any], path: str
    ) -> list[tuple[str, RelationshipType, str, str]]:
        """References this slice extracts, as (ref, type, mode, attribute)."""
        specs: list[tuple[str, RelationshipType, str, str]] = [
            (dep, RelationshipType.REFERENCES, "address", "depends_on")
            for dep in _string_list(raw, "depends_on", path)
        ]
        if tf_type == "aws_instance":
            specs += [
                (sg_id, RelationshipType.ATTACHED_TO, "native", "vpc_security_group_ids")
                for sg_id in _string_list(values, "vpc_security_group_ids", f"{path}.values")
            ]
            profile = _known(values.get("iam_instance_profile"))
            if profile:
                specs.append((profile, RelationshipType.REFERENCES, "arn", "iam_instance_profile"))
        elif tf_type == "aws_lambda_function":
            role = values.get("role")
            if role is not None:
                specs.append((str(role), RelationshipType.PERMISSION_ON, "arn", "role"))
        elif tf_type == "aws_db_instance":
            specs += [
                (sg_id, RelationshipType.ATTACHED_TO, "native", "vpc_security_group_ids")
                for sg_id in _string_list(values, "vpc_security_group_ids", f"{path}.values")
            ]
        return specs

    @staticmethod
    def _resolve(ref: str, mode: str, index: _DeclaredIndex) -> str:
        """Resolve a reference to a canonical target key without guessing.

        Order: an identity already declared in this document wins; then a
        fully-qualified reference (address or ARN) is parsed; anything else —
        including unknown markers and region-scoped native IDs with no
        region context — becomes an unresolved reference.
        """
        if _is_unknown(ref):
            return unresolved(ref).key
        if mode == "address":
            if ref in index.by_address:
                return index.by_address[ref]
            try:
                return parse_terraform_address(ref).key
            except IdParseError:
                return unresolved(ref).key
        if mode == "native":
            return index.by_native.get(ref) or unresolved(ref).key
        if mode == "arn":
            if ref in index.by_arn:
                return index.by_arn[ref]
            try:
                return parse_arn(ref).key
            except IdParseError:
                return unresolved(ref).key
        raise AssertionError(f"unknown resolution mode {mode!r}")
