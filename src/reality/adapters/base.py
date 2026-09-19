"""Adapter contracts.

Adapters are the only components that understand source-specific formats
(Terraform JSON here; AWS APIs, IAM policies, and CloudTrail later). The
contract is strictly read-only: an adapter parses input the caller supplies
and returns an :class:`AdapterResult`. It must never run subprocesses, never
write anywhere, and never mutate anything outside its own memory.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from reality.domain.models import (
    Coverage,
    Evidence,
    Relationship,
    Resource,
    TerraformChange,
)


class AdapterError(Exception):
    """Malformed or rejected adapter input.

    ``json_path`` locates the problem inside the input document (RFC 6901
    style, e.g. ``$.values.root_module.resources[0].address``) so callers
    can report exactly what was wrong instead of a stack trace.
    """

    def __init__(self, message: str, json_path: str = "$") -> None:
        self.json_path = json_path
        self.message = message
        super().__init__(f"{json_path}: {message}")


class AdapterResult(BaseModel):
    """What one adapter produced from one input.

    Everything a scan needs, kept separate: resources, relationship
    candidates, the evidence backing them, coverage of what could and could
    not be consulted, and (Terraform-specific) plan changes and address
    mappings. Empty collections mean "nothing found", never "nothing there".
    """

    model_config = ConfigDict(frozen=True)

    resources: tuple[Resource, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    coverage: tuple[Coverage, ...] = ()
    terraform_changes: tuple[TerraformChange, ...] = ()
    address_map: dict[str, str] = Field(default_factory=dict)


class Adapter(ABC):
    """Base class for read-only source adapters."""

    name: str = "adapter"

    @abstractmethod
    def collect(self, *args: Any, **kwargs: Any) -> AdapterResult:
        """Parse caller-supplied input into an AdapterResult."""
