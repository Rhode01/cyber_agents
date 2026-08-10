"""Agent orchestration DTOs.

``raw_input`` is untrusted: it is whatever a security tool emitted. The backend
normalises and stores it; the ai.engine fences it before it reaches a prompt.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from cyber_contracts import AgentKind, FindingCreate
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.finding import FindingRead


class AgentRunRequest(BaseModel):
    """A request to run one agent over one artifact."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(
        min_length=1,
        max_length=64,
        description="Tool that produced the artifact, e.g. nmap, trivy, zap, zeek.",
    )
    asset: str | None = Field(default=None, max_length=512)
    raw_input: str = Field(
        default="",
        description=(
            "Untrusted tool output. Treated as data, never as instructions. "
            "Leave empty to let the agent launch its own scan against ``asset``."
        ),
    )
    context: dict[str, Any] = Field(default_factory=dict, description="Optional trusted metadata.")
    run_id: UUID | None = Field(
        default=None,
        description="The pipeline run this agent execution belongs to, if any.",
    )
    persist: bool = Field(default=True, description="Store returned findings in PostgreSQL.")
    background: bool = Field(
        default=False,
        description="Enqueue on the arq worker instead of calling the ai.engine inline.",
    )


class AgentRunResponse(BaseModel):
    """The outcome of an agent run."""

    model_config = ConfigDict(extra="forbid")

    agent: AgentKind
    mode: Literal["inline", "background"]
    persisted: bool
    job_id: str | None = Field(default=None, description="Set when mode is background.")
    findings: list[FindingRead | FindingCreate] = Field(
        default_factory=list,
        description=(
            "Persisted findings when ``persist`` is true (carry id/timestamps); "
            "otherwise the wire findings as returned by the ai.engine."
        ),
    )
