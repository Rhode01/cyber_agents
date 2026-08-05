"""Agent request payloads that cross the backend -> ai.engine boundary.

The generic ``AnalyzeRequest`` used by the three stub agents still lives in
``ai_engine.schemas.requests`` - it never leaves that service in a form the
backend has to construct precisely. The vulnerability request does, because the
backend parses the scan, so it is defined here alongside the shape it carries.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from cyberagents_contracts.scan import NormalizedScan


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
