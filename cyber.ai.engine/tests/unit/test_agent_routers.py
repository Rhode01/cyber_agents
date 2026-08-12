"""Every agent router returns a payload that satisfies the shared contract."""

from __future__ import annotations

import pytest
from cyber_contracts import AgentKind, FindingBatch, FindingType, Severity
from httpx import AsyncClient

from tests.conftest import AGENTS, STUB_AGENTS


@pytest.mark.parametrize("agent", AGENTS)
async def test_analyze_returns_a_finding_shaped_payload(
    client: AsyncClient, analyze_payload: dict[str, object], agent: str
) -> None:
    response = await client.post(f"/agents/{agent}/analyze", json=analyze_payload)

    assert response.status_code == 200

    # Validated against the same model the backend uses, extra="forbid" included.
    batch = FindingBatch.model_validate(response.json())

    assert batch.agent is AgentKind(agent)
    assert batch.findings, "every agent must say something, even about a clean scan"

    for finding in batch.findings:
        assert finding.agent is AgentKind(agent)
        assert finding.source == "nmap"
        assert finding.detected_at.tzinfo is not None
        assert 0.0 <= finding.confidence <= 1.0


@pytest.mark.parametrize("agent", AGENTS)
async def test_analyze_rejects_unknown_fields(
    client: AsyncClient, analyze_payload: dict[str, object], agent: str
) -> None:
    payload = {**analyze_payload, "unexpected": "value"}

    response = await client.post(f"/agents/{agent}/analyze", json=payload)

    assert response.status_code == 422


@pytest.mark.parametrize("agent", STUB_AGENTS)
async def test_stub_agents_still_answer_with_one_placeholder(
    client: AsyncClient, analyze_payload: dict[str, object], agent: str
) -> None:
    """The three agents without a detection pipeline yet.

    Kept as an explicit assertion so that building one of them out is a visible
    change here, rather than something that quietly starts passing.
    """
    response = await client.post(f"/agents/{agent}/analyze", json=analyze_payload)
    batch = FindingBatch.model_validate(response.json())

    assert len(batch.findings) == 1
    finding = batch.findings[0]
    assert finding.asset == "host.example.internal"
    assert finding.severity is Severity.info
    assert finding.confidence == 0.0
    # The injection attempt survives into evidence as data, never as instruction.
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in finding.evidence["raw_input_preview"]


async def test_vulnerability_agent_reports_deterministic_findings_without_a_model(
    client: AsyncClient, analyze_payload: dict[str, object]
) -> None:
    """The rule engine alone must produce real findings.

    No API key is configured in the test environment and MCP is stubbed out, so
    everything asserted here came from the bundled knowledge base. If this test
    ever reduces to a single informational finding, the detector has been
    disarmed - which is exactly what a parser that drops `version` would do.
    """
    response = await client.post("/agents/vulnerability/analyze", json=analyze_payload)
    batch = FindingBatch.model_validate(response.json())

    by_type = {finding.finding_type: finding for finding in batch.findings}

    outdated = by_type[FindingType.outdated_service]
    assert outdated.severity is not Severity.info
    assert outdated.confidence > 0.0
    assert outdated.asset == "10.0.0.5", "the finding belongs to the scanned host"
    assert outdated.port == 22
    assert outdated.service == "ssh"
    assert outdated.protocol == "tcp"
    assert "OpenSSH" in outdated.description
    assert outdated.recommendation

    # Ranking is present, explainable, and not model output.
    priority = outdated.evidence["priority"]
    assert priority["rank"] >= 1
    assert 0 < priority["score"] <= priority["max_score"]
    assert set(priority["factors"]) == {
        "severity",
        "internet_exposure",
        "exploit_availability",
        "authentication_required",
        "business_criticality",
        "asset_type",
    }
    assert outdated.evidence["assessment"]["assessed_by"] == "rules-only"


async def test_injection_in_scanner_output_is_reported_without_a_model(
    client: AsyncClient, analyze_payload: dict[str, object]
) -> None:
    """Reporting an injection attempt must not depend on the model complying."""
    response = await client.post("/agents/vulnerability/analyze", json=analyze_payload)
    batch = FindingBatch.model_validate(response.json())

    injection = next(
        finding
        for finding in batch.findings
        if finding.finding_type is FindingType.prompt_injection_attempt
    )
    assert injection.severity is Severity.high
    assert "instruction-override" in injection.evidence["fact"]


async def test_cve_ids_reach_the_contract_field_not_just_evidence(
    client: AsyncClient,
) -> None:
    """A correlated CVE must land on ``cve_ids``, where the contract validates it."""
    payload = {
        "source": "nmap",
        "asset": "10.10.1.20",
        # OpenSSH 7.2 is inside the affected range of CVE-2018-15473.
        "raw_input": (
            "Nmap scan report for 10.10.1.20\n22/tcp open ssh OpenSSH 7.2 (protocol 2.0)\n"
        ),
        "context": {},
    }
    response = await client.post("/agents/vulnerability/analyze", json=payload)
    batch = FindingBatch.model_validate(response.json())

    cve_findings = [finding for finding in batch.findings if finding.cve_ids]
    assert cve_findings, "the knowledge base should have correlated a CVE here"
    assert "CVE-2018-15473" in cve_findings[0].cve_ids


async def test_unparseable_source_is_not_reported_as_clean(client: AsyncClient) -> None:
    """An artifact we could not read must not look like a clean scan."""
    payload = {
        "source": "some-unknown-scanner",
        "asset": "10.0.0.9",
        "raw_input": "nothing recognisable",
        "context": {},
    }
    response = await client.post("/agents/vulnerability/analyze", json=payload)
    batch = FindingBatch.model_validate(response.json())

    assert len(batch.findings) == 1
    finding = batch.findings[0]
    assert finding.finding_type is FindingType.informational
    assert "could not be parsed" in finding.title
