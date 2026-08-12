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

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CVE_PATTERN: Final = re.compile(r"CVE-\d{4}-\d{4,7}")


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


class FindingType(StrEnum):
    """What kind of problem a finding describes.

    Orthogonal to severity: a risky exposed service can be anything from info to
    critical depending on where it sits.

    Deliberately coarse. Phishing detection produces a dozen distinct *indicator*
    categories - display-name spoofing, lookalike domain, dangerous attachment -
    but those are evidence for one analyst decision about one message, so they
    live in ``evidence`` rather than each earning an enum member. Every value
    added here has to be added to a CHECK constraint in a migration, which is a
    good reason to keep the list short.
    """

    outdated_service = "outdated_service"
    risky_exposed_service = "risky_exposed_service"
    known_cve = "known_cve"
    weak_configuration = "weak_configuration"
    prompt_injection_attempt = "prompt_injection_attempt"
    phishing_message = "phishing_message"
    malicious_url = "malicious_url"
    informational = "informational"


class FindingStatus(StrEnum):
    """Where a finding sits in the analyst's workflow."""

    new = "new"
    triaged = "triaged"
    resolved = "resolved"
    false_positive = "false_positive"


class FindingCreate(BaseModel):
    """A finding as produced by an agent and accepted by the backend.

    Constraints here are deliberate and safe: this is the service-to-service
    contract, validated by Pydantic on both ends. The separate LLM-facing schema
    in ``ai_engine.agents.vulnerability.assessment_schema`` may carry no
    constraints at all - OpenAI's strict Structured Outputs mode forwards them
    unvalidated, where a rejection would fail every call.
    """

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    agent: AgentKind = Field(description="Detection agent that produced this finding.")
    finding_type: FindingType = Field(description="What kind of problem this describes.")
    title: str = Field(min_length=1, max_length=200, description="Short analyst-facing summary.")
    description: str = Field(
        min_length=1,
        description="Plain-language explanation of what was found and why it matters.",
    )
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
        description="Affected asset: host, URL, or message id. UNTRUSTED.",
    )
    service: str | None = Field(
        default=None,
        max_length=64,
        description="Affected service name, e.g. ssh, http. UNTRUSTED - from a banner.",
    )
    port: int | None = Field(default=None, ge=1, le=65535, description="Affected port.")
    protocol: str | None = Field(
        default=None, max_length=8, description="Transport protocol, e.g. tcp, udp."
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description="Correlated CVE identifiers. Never invented by a model.",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Untrusted supporting data. Treated as data, never as instructions.",
    )
    recommendation: str | None = Field(default=None, description="Suggested remediation.")
    status: FindingStatus = Field(
        default=FindingStatus.new, description="Analyst workflow state."
    )
    scan_id: UUID | None = Field(
        default=None, description="The scan intake record this came from, when there was one."
    )
    message_id: UUID | None = Field(
        default=None,
        description="The message intake record this came from, when there was one. "
        "Our own row id, not the RFC 5322 Message-ID header.",
    )
    run_id: UUID | None = Field(
        default=None, description="The pipeline run this finding came from, when there was one."
    )
    raw_reference: str | None = Field(
        default=None,
        max_length=512,
        description="Pointer back to the ingested artifact, e.g. scan://<uuid> or message://<uuid>.",
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

    @field_validator("cve_ids")
    @classmethod
    def _normalise_cve_ids(cls, value: list[str]) -> list[str]:
        """Uppercase, deduplicate, and reject anything not shaped like a CVE id.

        Worth validating: these reach an analyst as fact, and the rule engine is
        the only thing allowed to produce them.
        """
        seen: list[str] = []
        for raw in value:
            cve = raw.strip().upper()
            if not _CVE_PATTERN.fullmatch(cve):
                msg = f"not a CVE identifier: {raw!r}"
                raise ValueError(msg)
            if cve not in seen:
                seen.append(cve)
        return seen


class Finding(FindingCreate):
    """A persisted finding as returned by the backend."""

    id: UUID
    created_at: datetime
    updated_at: datetime


class FindingBatch(BaseModel):
    """A group of findings handed from one service to the other."""

    model_config = ConfigDict(extra="forbid")

    agent: AgentKind
    findings: list[FindingCreate] = Field(default_factory=list)
