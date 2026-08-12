"""Run DTOs.

A run is the persisted status of one pipeline execution from the Run Agent page.
``discovery`` is a JSON snapshot the UI renders, copied verbatim because it contains
untrusted scanner output.

``agent_statuses`` is different: it has **two** writers - the Run page and the arq
worker - and one JSONB column between them. Left unvalidated they drifted, and the
worker spent a while writing ``{"state": "completed", "findings": n}`` against a UI
reading ``{"state": "done", "count": n}``, which rendered as an unknown state with an
undefined count. Hence ``AgentStatusSnapshot``: strict on the way in, so a wrong key
is a 422 rather than a silently broken page.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from cyber_contracts import AgentKind
from pydantic import BaseModel, ConfigDict, Field


class RunCreate(BaseModel):
    """Create a new run with every agent initially pending."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=512, description="The asset being scanned.")
    mode: Literal["auto", "manual"] = Field(default="auto")


class AgentStatusSnapshot(BaseModel):
    """One agent's live state within a run.

    Written by both the Run page and the arq worker, so the field names are a
    contract rather than a convention. Mirrored in
    ``cyber.frontend/src/types/index.ts::AgentStatusSnapshot``.
    """

    model_config = ConfigDict(extra="forbid")

    state: Literal["pending", "running", "skipped", "done", "error"]
    count: int = Field(default=0, ge=0, description="Findings this agent produced.")
    error: str | None = Field(default=None, description="Why it failed, shown verbatim.")
    job_id: str | None = Field(
        default=None, description="The arq job, when the run was queued rather than inline."
    )


class RunUpdate(BaseModel):
    """Partial update of a run's live state."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["running", "completed", "completed_with_errors", "failed"] | None = None
    agent_statuses: dict[AgentKind, AgentStatusSnapshot] | None = Field(
        default=None,
        description="Per-agent status snapshot. Keying on AgentKind validates the "
        "agent name too, so a typo cannot create a phantom agent in the UI.",
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
    # Deliberately permissive where RunUpdate is strict: rows written before that
    # validation existed must still render, not 500 the runs page.
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
