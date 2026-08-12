"""The verification contract: re-checking whether a finding is actually fixed.

Separate from the finding contract on purpose. ``FindingBatch`` is
``extra="forbid"``, so a scan response cannot carry coverage alongside its
findings - and a host that has been fully remediated returns *no* findings, which
is exactly when coverage matters most. There would be nothing to attach it to.

**Coverage is the point of this module.** "Not detected" is not "fixed". It is also
what an offline host, a newly-firewalled port, a refused scan target, a service
moved to another port, and a narrower port range all look like. A verification pass
that reports only what it saw lets the backend mistake any of those for a
remediation, so what crosses this boundary is what was *covered* as well as what
was *observed*, and the backend may only resolve a finding when coverage proves the
re-check actually reached it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VerificationTarget(BaseModel):
    """One host and the ports a re-check must cover to be conclusive.

    The ports are those of the findings under verification, not a general sweep.
    Scanning exactly what is being verified is what makes the resulting coverage
    provable rather than assumed.
    """

    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=512, description="IP or explicitly local name.")
    ports: list[int] = Field(
        default_factory=list,
        description="Ports to cover. Empty means the host is reachable-checked only.",
    )


class VerificationRequest(BaseModel):
    """Ask the ai.engine to re-check a set of hosts and ports."""

    model_config = ConfigDict(extra="forbid")

    targets: list[VerificationTarget] = Field(min_length=1)
    context: dict[str, Any] = Field(
        default_factory=dict, description="Trusted metadata supplied by the backend."
    )


class HostCoverage(BaseModel):
    """What a re-check actually managed to examine on one host.

    ``ports_scanned`` is what the scanner was *asked* to examine, echoed back only
    when the scan succeeded and the host answered. It cannot be derived from the
    results: Nmap reports open ports only, so a port that is now closed is simply
    absent from its output - which is precisely what a fixed exposure looks like.
    Distinguishing "we looked and it was gone" from "we never looked" is the reason
    this model exists.
    """

    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=512)
    scan_ok: bool = Field(description="The scanner ran and produced usable output.")
    reachable: bool = Field(description="The host answered the scan.")
    ports_scanned: list[int] = Field(
        default_factory=list, description="Empty whenever the check was inconclusive."
    )
    detail: str = Field(
        default="",
        max_length=1024,
        description="Why an inconclusive check was inconclusive, shown to an operator.",
    )

    def covers(self, port: int | None) -> bool:
        """Was this port genuinely re-checked?

        A finding with no port - a package or container finding - can never be
        covered by a network scan, so it is refused here rather than being
        mistaken for a host-level result.
        """
        if port is None:
            return False
        return self.scan_ok and self.reachable and port in self.ports_scanned


class VerificationReport(BaseModel):
    """The result of one re-check pass.

    ``observed_candidate_ids`` are the ids the rule engine produced from the fresh
    scan. They are compared against stored findings' ``evidence.candidate_id``,
    which is content-addressed and stable across runs - see
    ``ai_engine.agents.vulnerability.candidates``. Deliberately ids and not
    findings: this pass re-runs the rules, it does not re-narrate them.
    """

    model_config = ConfigDict(extra="forbid")

    scanned_at: datetime = Field(description="When the re-check ran (UTC, tz-aware).")
    coverage: list[HostCoverage] = Field(default_factory=list)
    observed_candidate_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=list, description="Operator-facing remarks about the pass as a whole."
    )

    def coverage_for(self, host: str) -> HostCoverage | None:
        """Coverage for one host, or None when it was never examined."""
        for entry in self.coverage:
            if entry.host == host:
                return entry
        return None

    @property
    def conclusive(self) -> bool:
        """Did anything at all get covered?

        A report where nothing was covered is a valid answer - the MCP server was
        down, or every target was refused - and must not read as "all clear".
        """
        return any(entry.scan_ok and entry.reachable for entry in self.coverage)
