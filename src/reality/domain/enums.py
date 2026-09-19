"""Enumerations for the domain contracts.

These enums are the shared vocabulary between adapters, storage, services,
and reports. They are deliberately small: an adapter that needs a value not
listed here is probably modeling something that belongs in a model field
instead.
"""

from __future__ import annotations

from enum import StrEnum


class _StrEnum(StrEnum):
    """String-valued enum with a stable, lowercase value for serialization."""

    def __str__(self) -> str:
        return str(self.value)


class ResourceType(_StrEnum):
    """Kinds of resources the MVP knows about."""

    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    RDS_DB_INSTANCE = "rds_db_instance"
    S3_BUCKET = "s3_bucket"
    SECURITY_GROUP = "security_group"
    IAM_ROLE = "iam_role"
    TERRAFORM_RESOURCE = "terraform_resource"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class RelationshipType(_StrEnum):
    """How a source resource relates to a target resource."""

    DEPENDS_ON = "depends_on"
    ATTACHED_TO = "attached_to"
    PERMISSION_ON = "permission_on"
    CONTAINS = "contains"
    REFERENCES = "references"


class RelationshipOrigin(_StrEnum):
    """Which world a relationship claim came from."""

    TERRAFORM_DECLARED = "terraform_declared"
    AWS_OBSERVED = "aws_observed"
    IAM_POLICY = "iam_policy"
    CLOUDTRAIL = "cloudtrail"
    SIMULATION = "simulation"


class EvidenceSource(_StrEnum):
    """Which adapter produced a piece of evidence or a coverage record.

    ``RECONCILIATION`` is the exception: it names the reconciliation pass
    itself, which writes findings rather than evidence, and anchors the
    scan-run row those findings hang from.
    """

    TERRAFORM_PLAN = "terraform_plan"
    TERRAFORM_STATE = "terraform_state"
    AWS_RESOURCES = "aws_resources"
    IAM = "iam"
    CLOUDTRAIL = "cloudtrail"
    SIMULATION = "simulation"
    RECONCILIATION = "reconciliation"


class EvidenceType(_StrEnum):
    """The concrete shape of an evidence item."""

    CONFIG_REFERENCE = "config_reference"
    POLICY_STATEMENT = "policy_statement"
    API_EVENT = "api_event"
    OBSERVED_ATTRIBUTE = "observed_attribute"
    IDENTITY_MATCH = "identity_match"


class MappingBasis(_StrEnum):
    """Which identifier joined a Terraform declaration to an AWS resource.

    An ARN is fully qualified (it embeds region and account), so it is the
    authoritative basis; a native ID only joins when the state carried no
    usable ARN and exactly one observed resource of the same type shares it.
    Names are never a basis — a name match is not identity.
    """

    ARN = "arn"
    NATIVE_ID = "native_id"


class EvidenceStrength(_StrEnum):
    """Qualitative strength of a piece of evidence.

    Deliberately not numeric: evidence quality cannot be meaningfully
    compared as a number, and a fake precision would leak into conclusions.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class CoverageStatus(_StrEnum):
    """Whether a given evidence source could actually be consulted."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    NOT_REQUESTED = "not_requested"


class Conclusion(_StrEnum):
    """Safe conclusion about a relationship or resource's status.

    Frozen semantics from the build brief:

    - ``CONFIRMED``     declared (Terraform) and observed (AWS).
    - ``UNDOCUMENTED``  observed but not declared; the only basis for
                        hidden-dependency reporting.
    - ``POSSIBLE``      permission exists (IAM) but no observed usage.
    - ``DECLARED_ONLY`` declared but not observed; NOT the same as inactive.
    - ``UNKNOWN``       an input needed for the conclusion was unavailable;
                        absence of evidence, never evidence of absence.
    """

    CONFIRMED = "confirmed"
    UNDOCUMENTED = "undocumented"
    POSSIBLE = "possible"
    DECLARED_ONLY = "declared_only"
    UNKNOWN = "unknown"


class ChangeAction(_StrEnum):
    """Actions Terraform records for a resource in a plan.

    A plan's raw ``actions`` list uses these exact lowercase values, so
    ``ChangeAction(value)`` parses them directly.
    """

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"  # derived from the delete+create pair
    NOOP = "noop"


class ImpactBasis(_StrEnum):
    """What a blast-radius computation was based on."""

    TERRAFORM_PLAN = "terraform_plan"
    DISCOVERY_GRAPH = "discovery_graph"
