"""Scan intake DTOs.

``ScanRead`` deliberately omits ``raw_content``. The column holds up to 5 MB of
uploaded XML; shipping it to the browser on every poll would be wasteful, and the
frontend has no reason to render raw scanner output - interpreting it is the
agent's job.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from cyber_contracts import ScanFormat, ScanStatus
from pydantic import BaseModel, ConfigDict, Field


class ScanRead(BaseModel):
    """One scan intake record, as returned by the API."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: UUID
    filename: str
    format: ScanFormat
    size_bytes: int
    sha256: str
    asset: str | None
    status: ScanStatus
    job_id: str | None
    host_count: int
    finding_count: int
    error: str | None = Field(
        default=None, description="Why this scan produced no findings. Shown verbatim."
    )
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class ScanList(BaseModel):
    """A page of scans."""

    model_config = ConfigDict(extra="forbid")

    items: list[ScanRead] = Field(default_factory=list)
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)
