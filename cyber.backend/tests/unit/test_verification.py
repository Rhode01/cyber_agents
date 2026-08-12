"""The verification decision, one row of the outcome table per test.

``decide`` is pure - a stored finding plus a report in, an outcome out - so this
needs no database and runs everywhere.

The assertion that matters most is the negative one: **only a provably covered,
absent finding resolves.** Every other test here is a different way for a check to
be inconclusive, and each asserts that the status is left alone. Getting any of
them wrong means a host going offline silently closes findings.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from cyber_contracts import (
    FindingStatus,
    HostCoverage,
    NormalizedScan,
    ScanFormat,
    ScanHost,
    ScanPort,
    VerificationReport,
)

from app.models.finding import Finding
from app.services.verification import (
    OPEN_STATUSES,
    Outcome,
    candidate_id_of,
    decide,
    report_from_scan,
)

CANDIDATE = "cand_abc123"


def _finding(
    *,
    candidate: str | None = CANDIDATE,
    asset: str | None = "10.0.0.5",
    port: int | None = 22,
    status: str = FindingStatus.new.value,
) -> Finding:
    evidence: dict[str, object] = {"fact": "OpenSSH 7.2 is below the baseline."}
    if candidate is not None:
        evidence["candidate_id"] = candidate

    return Finding(
        id=uuid.uuid4(),
        agent="vulnerability",
        finding_type="outdated_service",
        title="Outdated OpenSSH",
        description="OpenSSH 7.2 is below the supported baseline.",
        severity="medium",
        confidence=0.8,
        source="nmap",
        asset=asset,
        service="ssh",
        port=port,
        protocol="tcp",
        cve_ids=[],
        evidence=evidence,
        status=status,
        detected_at=datetime.now(UTC),
    )


def _report(
    *,
    coverage: list[HostCoverage] | None = None,
    observed: list[str] | None = None,
) -> VerificationReport:
    return VerificationReport(
        scanned_at=datetime.now(UTC),
        coverage=coverage if coverage is not None else [],
        observed_candidate_ids=observed or [],
    )


def _covered(host: str = "10.0.0.5", ports: list[int] | None = None) -> HostCoverage:
    return HostCoverage(
        host=host, scan_ok=True, reachable=True, ports_scanned=ports or [22]
    )


# ------------------------------------------------------- the one that resolves --


def test_a_covered_and_absent_finding_resolves() -> None:
    """The only path that changes a status."""
    outcome = decide(_finding(), _report(coverage=[_covered()], observed=[]))

    assert outcome.outcome is Outcome.resolved
    assert outcome.resolves is True
    assert "no longer appears" in outcome.reason


def test_the_reason_names_what_was_re_scanned() -> None:
    """An auto-resolved finding has to be auditable after the fact."""
    outcome = decide(_finding(), _report(coverage=[_covered()], observed=[]))

    assert "22" in outcome.reason
    assert "10.0.0.5" in outcome.reason


# ---------------------------------------------------- covered but still there --


def test_a_covered_and_observed_finding_stays_open() -> None:
    outcome = decide(_finding(), _report(coverage=[_covered()], observed=[CANDIDATE]))

    assert outcome.outcome is Outcome.still_present
    assert outcome.resolves is False


def test_another_findings_candidate_does_not_keep_this_one_open() -> None:
    """The join is on the candidate id, not on "something was found here"."""
    outcome = decide(_finding(), _report(coverage=[_covered()], observed=["cand_other"]))

    assert outcome.outcome is Outcome.resolved


# ----------------------------------------------- every way to be inconclusive --


def test_an_unreachable_host_does_not_resolve() -> None:
    """The failure mode the whole design exists to prevent."""
    down = HostCoverage(
        host="10.0.0.5", scan_ok=True, reachable=False, detail="The host did not answer."
    )

    outcome = decide(_finding(), _report(coverage=[down], observed=[]))

    assert outcome.outcome is Outcome.unverified
    assert outcome.resolves is False
    assert "did not answer" in outcome.reason


def test_a_failed_scan_does_not_resolve() -> None:
    refused = HostCoverage(
        host="10.0.0.5",
        scan_ok=False,
        reachable=False,
        detail="10.0.0.5 is outside the configured scan allowlist.",
    )

    outcome = decide(_finding(), _report(coverage=[refused], observed=[]))

    assert outcome.outcome is Outcome.unverified
    assert "allowlist" in outcome.reason


def test_a_port_outside_the_scanned_range_does_not_resolve() -> None:
    """Partial coverage is the subtle one: the host answered, but not on this port."""
    outcome = decide(
        _finding(port=8080), _report(coverage=[_covered(ports=[22, 443])], observed=[])
    )

    assert outcome.outcome is Outcome.unverified
    assert outcome.resolves is False
    assert "8080" in outcome.reason


def test_a_host_absent_from_the_pass_does_not_resolve() -> None:
    outcome = decide(
        _finding(asset="10.0.0.9"), _report(coverage=[_covered()], observed=[])
    )

    assert outcome.outcome is Outcome.unverified
    assert "not part of this verification pass" in outcome.reason


def test_an_empty_report_resolves_nothing() -> None:
    """An MCP outage produces exactly this, and it must close nothing."""
    outcome = decide(_finding(), _report())

    assert outcome.resolves is False


# ---------------------------------------------------------------- can't verify --


def test_a_finding_with_no_port_is_unverifiable() -> None:
    """Package and container findings have nothing for a network scan to cover."""
    outcome = decide(_finding(port=None), _report(coverage=[_covered()], observed=[]))

    assert outcome.outcome is Outcome.unverifiable
    assert "package or container" in outcome.reason


def test_a_finding_with_no_candidate_id_is_unverifiable() -> None:
    """Findings from agents without a rule engine cannot be joined to a scan."""
    outcome = decide(_finding(candidate=None), _report(coverage=[_covered()], observed=[]))

    assert outcome.outcome is Outcome.unverifiable
    assert "candidate id" in outcome.reason


def test_a_finding_with_no_asset_is_unverifiable() -> None:
    outcome = decide(_finding(asset=None), _report(coverage=[_covered()], observed=[]))

    assert outcome.outcome is Outcome.unverifiable


@pytest.mark.parametrize(
    "status", [FindingStatus.resolved.value, FindingStatus.false_positive.value]
)
def test_a_closed_finding_is_never_re_opened(status: str) -> None:
    """A regression comes back as a new row, because dedupe_key includes the run.

    Re-opening here would fight that model and lose the history it exists to keep.
    """
    outcome = decide(_finding(status=status), _report(coverage=[_covered()], observed=[CANDIDATE]))

    assert outcome.outcome is Outcome.unverifiable
    assert "does not re-open" in outcome.reason


def test_triaged_findings_are_still_verified() -> None:
    """Triaged means an analyst looked at it, not that it stopped mattering."""
    assert FindingStatus.triaged.value in OPEN_STATUSES

    outcome = decide(
        _finding(status=FindingStatus.triaged.value),
        _report(coverage=[_covered()], observed=[]),
    )

    assert outcome.outcome is Outcome.resolved


# ------------------------------------------------------------------ plumbing --


def test_the_candidate_id_is_read_out_of_evidence() -> None:
    assert candidate_id_of(_finding()) == CANDIDATE
    assert candidate_id_of(_finding(candidate=None)) is None


def test_a_non_string_candidate_id_is_ignored() -> None:
    """Evidence is untrusted; its shape is guaranteed by nothing."""
    finding = _finding()
    finding.evidence = {**finding.evidence, "candidate_id": 12345}

    assert candidate_id_of(finding) is None


# --------------------------------------------------- coverage from a scan file --


def _scan(
    host_status: str = "up",
    open_ports: list[int] | None = None,
    requested: list[int] | None = None,
) -> NormalizedScan:
    return NormalizedScan(
        format=ScanFormat.nmap_xml,
        scanner="nmap",
        hosts=[
            ScanHost(
                address="10.0.0.5",
                status=host_status,
                ports=[
                    ScanPort(port=port, protocol="tcp", state="open")
                    for port in (open_ports if open_ports is not None else [22])
                ],
            )
        ],
        ports_requested=requested if requested is not None else [22, 80, 443],
    )


def test_coverage_comes_from_the_requested_range_not_the_open_ports() -> None:
    """The distinction the whole automatic path depends on.

    Nmap lists only OPEN ports under each host, so a remediated port vanishes from
    the results. Deriving coverage from them would make every fix unverifiable: the
    finding disappears, and so does the proof that anyone looked. `<scaninfo
    services>` records what was actually examined.
    """
    report = report_from_scan(_scan(open_ports=[80], requested=[22, 80, 443]), findings=[])

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.ports_scanned == [22, 80, 443]
    # 22 was scanned and found closed. That is exactly a remediated exposure.
    assert coverage.covers(22) is True
    assert coverage.covers(8080) is False, "outside the requested range"


def test_a_remediated_port_resolves_through_the_uploaded_scan_path() -> None:
    """End to end for the automatic trigger, without a database."""
    report = report_from_scan(_scan(open_ports=[80], requested=[22, 80]), findings=[])

    assert decide(_finding(port=22), report).outcome is Outcome.resolved


def test_a_scan_that_does_not_state_its_range_resolves_nothing() -> None:
    """Older uploads and non-Nmap formats. Absence proves nothing without it."""
    report = report_from_scan(_scan(open_ports=[80], requested=[]), findings=[])

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.ports_scanned == []
    assert coverage.covers(22) is False
    assert "does not state which ports" in coverage.detail
    assert decide(_finding(), report).outcome is Outcome.unverified


def test_a_scan_recording_a_down_host_covers_nothing() -> None:
    report = report_from_scan(_scan(host_status="down"), findings=[])

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.reachable is False
    assert coverage.ports_scanned == []
    assert coverage.covers(22) is False
    assert report.conclusive is False


def test_the_scans_own_findings_supply_the_observed_ids() -> None:
    from cyber_contracts import AgentKind, FindingCreate, FindingType, Severity

    fresh = FindingCreate(
        agent=AgentKind.vulnerability,
        finding_type=FindingType.outdated_service,
        title="Outdated OpenSSH",
        description="Still there.",
        severity=Severity.medium,
        confidence=0.8,
        source="nmap",
        asset="10.0.0.5",
        port=22,
        evidence={"candidate_id": CANDIDATE},
        detected_at=datetime.now(UTC),
    )

    report = report_from_scan(_scan(), findings=[fresh])

    assert report.observed_candidate_ids == [CANDIDATE]
    # And therefore the prior finding stays open rather than resolving.
    assert decide(_finding(), report).outcome is Outcome.still_present
