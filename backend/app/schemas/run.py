"""Run DTOs.

A run is the persisted status of one pipeline execution from the Run Agent page.
``agent_statuses`` and ``discovery`` are JSON snapshots the UI renders; they are
copied verbatim because they may contain untrusted scanner output.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RunCreate(BaseModel):
    """Create a new run with every agent initially pending."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=512, description="The asset being scanned.")
    mode: Literal["auto", "manual"] = Field(default="auto")


class RunUpdate(BaseModel):
    """Partial update of a run's live state."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["running", "completed", "completed_with_errors", "failed"] | None = None
    agent_statuses: dict[str, Any] | None = Field(
        default=None, description="Per-agent status snapshot keyed by agent kind."
    )
    discovery: dict[str, Any] | None = Field(
        default=None, description="The discovery report for this run, or null."
    )


class RunRead(BaseModel):
    """A run as returned to the UI."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    target: str
    mode: Literal["auto", "manual"]
    status: Literal["running", "completed", "completed_with_errors", "failed"]
    agent_statuses: dict[str, Any] = Field(default_factory=dict)
    discovery: dict[str, Any] | None = None
    started_at: datetime
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RunList(BaseModel):
    """A list of runs, newest first."""

    model_config = ConfigDict(extra="forbid")

    items: list[RunRead] = Field(default_factory=list)
    total: int = Field(ge=0)


class RunStatus(BaseModel):
    """Whether a scan is currently in progress and which target it is on."""

    model_config = ConfigDict(extra="forbid")

    scanning: bool
    current: RunRead | None = None
