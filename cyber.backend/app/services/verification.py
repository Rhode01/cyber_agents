"""Deciding whether a finding is actually fixed.

The backend owns this because it is the only side with history: the ai.engine
reports what one scan covered and observed, and this compares that against what is
stored.

**One rule governs everything here: a finding may only be resolved when coverage
proves it was genuinely re-checked.** "Not detected" is also what an offline host, a
refused scan target, a newly-filtered port and a narrower port range look like.
Resolving on absence alone would mean a host going offline silently closes every
finding on it - a dashboard that is confidently wrong, which is worse than one that
says nothing.

So there are four outcomes, and only one of them changes a status:

``unverifiable``  the finding has no port, so no network scan can ever cover it
``unverified``    it was not covered, and the reason is recorded
``still_present`` it was covered and the rules fired again
``resolved``      it was covered and did not fire

Each outcome appends to ``evidence.verification``, so a finding carries the history
of every attempt to confirm it rather than just its current state. That list is
platform-generated and sits alongside ``priority`` and ``assessment`` in an
otherwise-untrusted blob, following what those already do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from cyber_contracts import (
    FindingCreate,
    FindingStatus,
    HostCoverage,
    NormalizedScan,
    VerificationReport,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud
from app.core.logging import get_logger
from app.models.finding import Finding

logger = get_logger(__name__)

# Statuses a verification pass is allowed to look at. A resolved finding is not
# re-opened here: a regression comes back as a *new* finding row, because
# `crud_finding.dedupe_key` includes run_id/scan_id precisely so "a re-scan always
# records what it saw". Closing the old row and opening a new one is the history.
OPEN_STATUSES: tuple[str, ...] = (FindingStatus.new.value, FindingStatus.triaged.value)


class Outcome(StrEnum):
    """What one verification attempt concluded about one finding."""

    unverifiable = "unverifiable"
    unverified = "unverified"
    still_present = "still_present"
    resolved = "resolved"


@dataclass(frozen=True, slots=True)
class FindingOutcome:
    """One finding's verification result, and why."""

    finding_id: UUID
    outcome: Outcome
    reason: str

    @property
    def resolves(self) -> bool:
        return self.outcome is Outcome.resolved


@dataclass(slots=True)
class VerificationOutcome:
    """The result of one pass over a set of findings."""

    outcomes: list[FindingOutcome] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for entry in self.outcomes:
            tally[entry.outcome.value] = tally.get(entry.outcome.value, 0) + 1
        return tally

    @property
    def resolved_ids(self) -> list[UUID]:
        return [entry.finding_id for entry in self.outcomes if entry.resolves]


def candidate_id_of(finding: Finding) -> str | None:
    """The rule-engine id this finding came from, if it carries one.

    Lives in ``evidence`` rather than a column. Findings from agents without a rule
    engine have none, and cannot be verified this way.
    """
    evidence = finding.evidence or {}
    value = evidence.get("candidate_id")
    return value if isinstance(value, str) and value else None


def decide(finding: Finding, report: VerificationReport) -> FindingOutcome:
    """Decide one finding's fate against one report. Pure - no I/O, no mutation."""
    if finding.status not in OPEN_STATUSES:
        return FindingOutcome(
            finding.id,
            Outcome.unverifiable,
            f"Already {finding.status}; a verification pass does not re-open findings.",
        )

    candidate = candidate_id_of(finding)
    if candidate is None:
        return FindingOutcome(
            finding.id,
            Outcome.unverifiable,
            "This finding carries no rule-engine candidate id, so there is nothing to "
            "re-check it against.",
        )

    if finding.port is None:
        return FindingOutcome(
            finding.id,
            Outcome.unverifiable,
            "This finding has no network port - it came from a package or container "
            "manifest - so a network scan can never cover it.",
        )

    if not finding.asset:
        return FindingOutcome(
            finding.id, Outcome.unverifiable, "This finding names no asset to re-check."
        )

    coverage = report.coverage_for(finding.asset)
    if coverage is None:
        return FindingOutcome(
            finding.id,
            Outcome.unverified,
            f"{finding.asset} was not part of this verification pass.",
        )

    if not coverage.covers(finding.port):
        # The important branch. Everything that is not provable coverage lands
        # here and changes nothing.
        return FindingOutcome(
            finding.id,
            Outcome.unverified,
            coverage.detail
            or (
                f"Port {finding.port} on {finding.asset} was not covered by this scan, "
                "so its absence proves nothing."
            ),
        )

    if candidate in set(report.observed_candidate_ids):
        return FindingOutcome(
            finding.id,
            Outcome.still_present,
            f"Re-checked on {report.scanned_at.date().isoformat()} and still detected.",
        )

    return FindingOutcome(
        finding.id,
        Outcome.resolved,
        f"Port {finding.port} on {finding.asset} was re-scanned on "
        f"{report.scanned_at.date().isoformat()} and this no longer appears.",
    )


def _entry(outcome: FindingOutcome, report: VerificationReport, source: str) -> dict[str, Any]:
    """The record appended to ``evidence.verification``."""
    return {
        "outcome": outcome.outcome.value,
        "reason": outcome.reason,
        "verified_at": report.scanned_at.isoformat(),
        "recorded_at": datetime.now(UTC).isoformat(),
        "source": source,
        "note": "Platform-generated. Only a covered, absent finding is resolved.",
    }


async def apply_verification(
    session: AsyncSession,
    *,
    findings: list[Finding],
    report: VerificationReport,
    source: str,
) -> VerificationOutcome:
    """Decide every finding and persist the outcomes.

    ``source`` identifies what drove the pass - ``scan://<id>`` or
    ``recheck://<id>`` - so a finding's history says what re-checked it.
    """
    result = VerificationOutcome()

    for finding in findings:
        outcome = decide(finding, report)
        result.outcomes.append(outcome)

        history = list(finding.evidence.get("verification", []) or [])
        history.append(_entry(outcome, report, source))
        # Reassigned, not appended in place: SQLAlchemy does not track mutations
        # inside a plain JSONB dict, so an in-place append would never persist.
        finding.evidence = {**finding.evidence, "verification": history}

        if outcome.resolves:
            finding.status = FindingStatus.resolved.value

    if result.outcomes:
        await session.commit()

    logger.info(
        "verification.applied",
        source=source,
        conclusive=report.conclusive,
        **result.counts(),
    )
    return result


def report_from_scan(
    scan: NormalizedScan, *, findings: list[FindingCreate], scanned_at: datetime | None = None
) -> VerificationReport:
    """Build a report from a scan the backend parsed itself.

    An uploaded scan needs no re-scan to verify against: the artifact states which
    hosts answered and which ports each reported, which is exactly coverage. Asking
    the ai.engine to scan again would be slower and no more truthful.

    ``ports_scanned`` comes from ``scan.ports_requested`` - Nmap's ``<scaninfo
    services>`` - and **not** from the ports listed under each host. Those are only
    the ports found *open*, so a port that was scanned and found closed is absent
    from them, which is exactly what a remediated exposure looks like. Deriving
    coverage from the results would therefore make every fix unverifiable: the
    finding disappears, and so does the evidence that anyone looked.

    A report that does not state its requested range covers nothing. Older uploads
    and non-Nmap formats fall into that, and they leave findings open rather than
    resolving them on an assumption.
    """
    requested = sorted(set(scan.ports_requested))
    coverage: list[HostCoverage] = []
    for host in scan.hosts:
        reachable = host.status.lower() != "down"
        conclusive = reachable and bool(requested)
        if not reachable:
            detail = "The scan recorded this host as down, so nothing on it was checked."
        elif not requested:
            detail = (
                "The report does not state which ports were scanned, so a finding's "
                "absence from it proves nothing."
            )
        else:
            detail = ""
        coverage.append(
            HostCoverage(
                host=host.address,
                scan_ok=True,
                reachable=reachable,
                ports_scanned=requested if conclusive else [],
                detail=detail,
            )
        )

    observed = [
        candidate
        for candidate in (
            (finding.evidence or {}).get("candidate_id") for finding in findings
        )
        if isinstance(candidate, str) and candidate
    ]

    return VerificationReport(
        scanned_at=scanned_at or scan.started_at or datetime.now(UTC),
        coverage=coverage,
        observed_candidate_ids=list(dict.fromkeys(observed)),
        notes=[
            "Coverage derived from the uploaded scan's own <scaninfo> range, not from "
            "the ports it found open."
            if requested
            else "The uploaded scan did not state which ports it examined, so nothing "
            "in it can resolve a finding."
        ],
    )


async def verify_from_scan(
    session: AsyncSession,
    *,
    normalized: NormalizedScan,
    batch_findings: list[FindingCreate],
    source: str,
) -> VerificationOutcome:
    """Verify prior open findings against a scan that just completed."""
    assets = [host.address for host in normalized.hosts]
    if not assets:
        return VerificationOutcome()

    report = report_from_scan(normalized, findings=batch_findings)
    candidates_now = set(report.observed_candidate_ids)

    stored = await crud.finding.open_by_candidate_ids(
        session, assets=assets, statuses=OPEN_STATUSES
    )
    # Findings this very scan just created are not evidence about themselves.
    prior = [
        finding
        for finding in stored
        if candidate_id_of(finding) is None or finding.raw_reference != source
    ]
    logger.info(
        "verification.from_scan",
        source=source,
        assets=len(assets),
        prior=len(prior),
        observed=len(candidates_now),
    )
    return await apply_verification(
        session, findings=prior, report=report, source=source
    )
