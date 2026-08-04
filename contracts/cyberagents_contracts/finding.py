"""The Finding contract - the single source of truth for both services.

The backend owns persistence and the ai.engine owns detection, and neither
imports the other. This module is the one place the shape they exchange is
defined; both consume it as a Poetry path dependency installed into their own
separate virtualenvs.

Security note: ``Finding.evidence`` carries data lifted straight out of an
untrusted artifact - an email body, an HTTP response, a log line. It is stored
and displayed, never interpolated into a prompt without being fenced first (see
``ai_engine.agents.common.untrusted``).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentKind(StrEnum):
    """Which detection agent produced a finding."""

    vulnerability = "vulnerability"
    phishing = "phishing"
    network = "network"
    webapp = "webapp"


class Severity(StrEnum):
    """Analyst-facing severity, ordered low to high."""

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class FindingCreate(BaseModel):
    """A finding as produced by an agent and accepted by the backend."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    agent: AgentKind = Field(description="Detection agent that produced this finding.")
    title: str = Field(min_length=1, max_length=200, description="Short analyst-facing summary.")
    description: str = Field(min_length=1, description="What was found and why it matters.")
    severity: Severity = Field(description="Analyst-facing severity.")
    confidence: float = Field(ge=0.0, le=1.0, description="Agent confidence, 0.0 to 1.0.")
    source: str = Field(
        min_length=1,
        max_length=64,
        description="Tool that produced the underlying artifact, e.g. nmap, trivy, zap, zeek.",
    )
    asset: str | None = Field(
        default=None,
        max_length=512,
        description="Affected asset: host, URL, or message id.",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Untrusted supporting data. Treated as data, never as instructions.",
    )
    recommendation: str | None = Field(default=None, description="Suggested remediation.")
    raw_reference: str | None = Field(
        default=None,
        max_length=512,
        description="Pointer back to the ingested artifact this was derived from.",
    )
    detected_at: datetime = Field(description="When the underlying activity was observed (UTC).")

    @field_validator("detected_at")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        """Reject naive datetimes so stored timestamps are never ambiguous."""
        if value.tzinfo is None:
            msg = "detected_at must be timezone-aware"
            raise ValueError(msg)
        return value


class Finding(FindingCreate):
    """A persisted finding as returned by the backend."""

    id: UUID
    created_at: datetime


class FindingBatch(BaseModel):
    """A group of findings handed from one service to the other."""

    model_config = ConfigDict(extra="forbid")

    agent: AgentKind
    findings: list[FindingCreate] = Field(default_factory=list)
