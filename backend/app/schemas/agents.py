"""Agent orchestration DTOs.

``raw_input`` is untrusted: it is whatever a security tool emitted. The backend
normalises and stores it; the ai.engine fences it before it reaches a prompt.
"""

from __future__ import annotations

from typing import Any, Literal

from cyberagents_contracts import AgentKind
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
        description="Untrusted tool output. Treated as data, never as instructions."
    )
    context: dict[str, Any] = Field(default_factory=dict, description="Optional trusted metadata.")
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
    findings: list[FindingRead] = Field(default_factory=list)
