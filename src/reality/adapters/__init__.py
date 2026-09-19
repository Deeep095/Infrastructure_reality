"""Read-only source adapters."""

from reality.adapters.aws_resources import AwsResourcesAdapter
from reality.adapters.base import Adapter, AdapterError, AdapterResult
from reality.adapters.cloudtrail import CloudTrailAdapter
from reality.adapters.iam import IamAdapter
from reality.adapters.terraform import SUPPORTED_TYPES, TerraformAdapter

__all__ = [
    "Adapter",
    "AdapterError",
    "AdapterResult",
    "AwsResourcesAdapter",
    "CloudTrailAdapter",
    "IamAdapter",
    "SUPPORTED_TYPES",
    "TerraformAdapter",
]
