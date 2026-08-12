"""Finding DTOs.

The wire shape is not redefined here: it is imported from the shared
``cyber_contracts`` package, which is the single source of truth that both
the backend and the ai.engine install into their own separate virtualenvs. This
module only adds the read model that maps out of the ORM.
"""

from __future__ import annotations

from uuid import UUID

from cyber_contracts import (
    AgentKind,
    Finding,
    FindingBatch,
    FindingCreate,
    FindingStatus,
    FindingType,
    Severity,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    "FindingVerifyRequest",
    "FindingVerifyResponse",
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


class FindingVerifyRequest(BaseModel):
    """Ask the platform to re-check findings after a fix.

    Either specific findings or every open finding on one asset. Requiring one of
    the two is deliberate: a re-check launches a scan, so there is no "verify
    everything" default that could sweep the estate by accident.
    """

    model_config = ConfigDict(extra="forbid")

    finding_ids: list[UUID] = Field(
        default_factory=list, max_length=200, description="Specific findings to re-check."
    )
    asset: str | None = Field(
        default=None, max_length=512, description="Re-check every open finding on this asset."
    )

    @model_validator(mode="after")
    def _require_a_scope(self) -> FindingVerifyRequest:
        if not self.finding_ids and not self.asset:
            msg = "Provide finding_ids or asset: a re-check needs a scope."
            raise ValueError(msg)
        return self


class FindingVerifyResponse(BaseModel):
    """Acknowledgement that a re-check has been queued."""

    model_config = ConfigDict(extra="forbid")

    queued: int = Field(ge=0, description="How many open findings will be re-checked.")
    job_id: str | None = Field(
        default=None, description="The arq job, or null when the queue deduplicated it."
    )
    detail: str = Field(description="What will happen, in one line for the UI.")
