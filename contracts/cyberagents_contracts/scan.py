"""The normalized scan contract.

Parsing lives in the backend, reasoning lives in the ai.engine, so the *parsed*
shape crosses the wire and has to be defined once for both.

**Every string field on ``ScanHost`` and ``ScanPort`` is attacker-controllable.**
Hostnames, service names, product names, version strings and banner extra-info
are whatever the scanned machine chose to answer with, and a compromised host
answers with whatever its operator wants. They are carried through verbatim -
deliberately, because sanitising them at the parse boundary would destroy the
evidence the injection detector needs and would imply a safety that does not
exist. They are fenced exactly once, at the prompt boundary, by
``ai_engine.agents.common.untrusted.wrap_untrusted``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ScanFormat(StrEnum):
    """Scanner output formats the platform can ingest."""

    nmap_xml = "nmap_xml"
    openvas_xml = "openvas_xml"


class ScanStatus(StrEnum):
    """Lifecycle of one uploaded scan.

    ``failed`` is terminal but retryable - it carries the reason in
    ``Scan.error`` rather than silently producing degraded findings.
    """

    pending = "pending"
    parsing = "parsing"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"


class ScanPort(BaseModel):
    """One open port on one host. All string fields are UNTRUSTED."""

    model_config = ConfigDict(extra="forbid")

    port: int = Field(ge=1, le=65535)
    protocol: str = Field(max_length=8, description="tcp or udp.")
    state: str = Field(max_length=16, description="Nmap port state; only 'open' is kept.")
    service: str | None = Field(default=None, max_length=64, description="UNTRUSTED.")
    product: str | None = Field(default=None, max_length=256, description="UNTRUSTED.")
    version: str | None = Field(default=None, max_length=128, description="UNTRUSTED.")
    extrainfo: str | None = Field(default=None, max_length=256, description="UNTRUSTED.")
    cpe: list[str] = Field(default_factory=list, description="UNTRUSTED.")


class ScanHost(BaseModel):
    """One host in a scan. ``address`` and ``hostnames`` are UNTRUSTED."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(min_length=1, max_length=64)
    hostnames: list[str] = Field(default_factory=list, description="UNTRUSTED.")
    status: str = Field(max_length=16, description="up or down.")
    ports: list[ScanPort] = Field(default_factory=list)


class NormalizedScan(BaseModel):
    """A scanner report reduced to the shape the agents reason over."""

    model_config = ConfigDict(extra="forbid")

    format: ScanFormat
    scanner: str = Field(max_length=64, description="UNTRUSTED - from the report itself.")
    scanner_version: str | None = Field(default=None, max_length=64, description="UNTRUSTED.")
    started_at: datetime | None = Field(default=None, description="When the scan ran, if stated.")
    hosts: list[ScanHost] = Field(default_factory=list)

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def open_port_count(self) -> int:
        return sum(len(host.ports) for host in self.hosts)
