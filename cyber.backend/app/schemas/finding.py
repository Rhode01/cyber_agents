"""Finding DTOs.

The wire shape is not redefined here: it is imported from the shared
``cyberagents_contracts`` package, which is the single source of truth that both
the backend and the ai.engine install into their own separate virtualenvs. This
module only adds the read model that maps out of the ORM.
"""

from __future__ import annotations

from cyberagents_contracts import (
    AgentKind,
    Finding,
    FindingBatch,
    FindingCreate,
    FindingStatus,
    FindingType,
    Severity,
)
from pydantic import BaseModel, ConfigDict, Field

# Re-exported so the rest of the backend imports one consistent surface.
FindingBatchCreate = FindingBatch

__all__ = [
    "AgentKind",
    "FindingBatchCreate",
    "FindingCreate",
    "FindingList",
    "FindingRead",
    "FindingStatus",
    "FindingStatusUpdate",
    "FindingType",
    "Severity",
]


class FindingRead(Finding):
    """A persisted finding, built directly from the ORM object."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")


class FindingList(BaseModel):
    """A page of findings."""

    model_config = ConfigDict(extra="forbid")

    items: list[FindingRead] = Field(default_factory=list)
    total: int = Field(ge=0, description="Number of rows matching the filter, ignoring paging.")
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class FindingStatusUpdate(BaseModel):
    """The only mutable part of a finding.

    Everything else is what an agent observed, and rewriting an observation would
    destroy the audit trail. Triage state is the analyst's to change.
    """

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
