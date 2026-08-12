"""Agent request payloads that cross the backend -> ai.engine boundary.

The generic ``AnalyzeRequest`` used by the remaining stub agents still lives in
``app.schemas.requests`` inside the ai.engine - it never leaves that service in a
form the backend has to construct precisely. The vulnerability and phishing
requests do, because the backend parses the artifact, so they are defined here
alongside the shapes they carry.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from cyber_contracts.message import NormalizedMessage
from cyber_contracts.scan import NormalizedScan


class VulnerabilityAnalyzeRequest(BaseModel):
    """One parsed scan for the vulnerability agent to interpret."""

    model_config = ConfigDict(extra="forbid")

    scan_id: UUID = Field(description="The backend's intake record, echoed into raw_reference.")
    source: str = Field(
        min_length=1, max_length=64, description="Tool that produced the scan, e.g. nmap."
    )
    asset: str | None = Field(
        default=None, max_length=512, description="Optional operator-supplied scope label."
    )
    scan: NormalizedScan = Field(description="Parsed scan. Every string inside is UNTRUSTED.")
    context: dict[str, Any] = Field(
        default_factory=dict, description="Trusted metadata supplied by the backend."
    )


class EnrichmentPolicy(BaseModel):
    """What the phishing agent is permitted to look up outside this process.

    Split from ``context`` because it is a *permission*, not metadata: the
    analyst decides per submission how far the platform may reach, and the
    ai.engine additionally has its own kill switch. Both must agree before any
    request leaves the box.
    """

    model_config = ConfigDict(extra="forbid")

    resolve_dns: bool = Field(
        default=True,
        description="Look up the sender domain's real SPF/DMARC/DKIM/MX records. "
        "Queries a resolver, never the suspect host.",
    )
    domain_age: bool = Field(
        default=True,
        description="Look up registration age over RDAP. Queries a registry, never "
        "the suspect host.",
    )
    fetch_urls: bool = Field(
        default=False,
        description="Fetch the linked pages to follow redirects and inspect for a "
        "credential form. This is the only option that CONTACTS THE SUSPECT HOST, "
        "which both reveals that the message is under investigation and exposes "
        "this platform to whatever the host serves. Off unless asked for.",
    )
    max_urls: int = Field(
        default=5, ge=1, le=20, description="Cap on how many links are enriched."
    )


class PhishingAnalyzeRequest(BaseModel):
    """One parsed message for the phishing agent to interpret."""

    model_config = ConfigDict(extra="forbid")

    intake_id: UUID = Field(
        description="The backend's `messages` row. NOT the RFC 5322 Message-ID, "
        "which is attacker-supplied and lives on `message.message_id`."
    )
    source: str = Field(
        min_length=1,
        max_length=64,
        description="Where the artifact came from, e.g. eml-upload or url-submission.",
    )
    asset: str | None = Field(
        default=None,
        max_length=512,
        description="The sender address, or the submitted URL. UNTRUSTED.",
    )
    message: NormalizedMessage = Field(
        description="Parsed message. Almost every string inside is UNTRUSTED."
    )
    enrichment: EnrichmentPolicy = Field(default_factory=EnrichmentPolicy)
    context: dict[str, Any] = Field(
        default_factory=dict, description="Trusted metadata supplied by the backend."
    )
