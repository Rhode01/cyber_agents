"""Agent request and response DTOs.

``AnalyzeResponse`` is the shared ``FindingBatch`` itself rather than a subclass:
the backend validates the response against that exact model with
``extra="forbid"``, so adding a field here would break the contract rather than
extend it. Anything the ai.engine wants to report alongside findings belongs in
a finding's ``evidence``.
"""

from __future__ import annotations

from typing import Any, Literal

from cyberagents_contracts import FindingBatch
from pydantic import BaseModel, ConfigDict, Field

AnalyzeResponse = FindingBatch


class AnalyzeRequest(BaseModel):
    """One artifact for one agent to analyse."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(
        min_length=1,
        max_length=64,
        description="Tool that produced the artifact, e.g. nmap, trivy, zap, zeek.",
    )
    asset: str | None = Field(
        default=None, max_length=512, description="Affected host, URL, or message id."
    )
    raw_input: str = Field(
        default="",
        description=(
            "Untrusted tool output. Fenced by the agent before it reaches a prompt "
            "and never treated as instructions. Leave empty to let the agent launch "
            "its own scan against ``asset``."
        ),
    )
    context: dict[str, Any] = Field(
        default_factory=dict, description="Trusted metadata supplied by the backend."
    )


class HealthResponse(BaseModel):
    """Liveness of the ai.engine, plus the resolved LLM configuration."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    service: str = "ai.engine"
    version: str
    app_env: str
    agents: list[str] = Field(description="Agent routers currently mounted.")
    llm: dict[str, Any] = Field(description="Resolved model configuration. Never includes the key.")


__all__ = ["AnalyzeRequest", "AnalyzeResponse", "HealthResponse"]
