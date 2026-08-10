"""Every agent router returns a payload that satisfies the shared contract."""

from __future__ import annotations

import pytest
from cyber_contracts import AgentKind, FindingBatch
from httpx import AsyncClient

from tests.conftest import AGENTS


@pytest.mark.parametrize("agent", AGENTS)
async def test_analyze_returns_a_finding_shaped_payload(
    client: AsyncClient, analyze_payload: dict[str, object], agent: str
) -> None:
    response = await client.post(f"/agents/{agent}/analyze", json=analyze_payload)

    assert response.status_code == 200

    # Validated against the same model the backend uses, extra="forbid" included.
    batch = FindingBatch.model_validate(response.json())

    assert batch.agent is AgentKind(agent)
    assert len(batch.findings) == 1

    finding = batch.findings[0]
    assert finding.agent is AgentKind(agent)
    assert finding.source == "nmap"
    assert finding.asset == "host.example.internal"
    assert finding.detected_at.tzinfo is not None
    assert 0.0 <= finding.confidence <= 1.0


@pytest.mark.parametrize("agent", AGENTS)
async def test_analyze_rejects_unknown_fields(
    client: AsyncClient, analyze_payload: dict[str, object], agent: str
) -> None:
    payload = {**analyze_payload, "unexpected": "value"}

    response = await client.post(f"/agents/{agent}/analyze", json=payload)

    assert response.status_code == 422


@pytest.mark.parametrize("agent", AGENTS)
async def test_untrusted_input_is_stored_as_evidence_not_acted_on(
    client: AsyncClient, analyze_payload: dict[str, object], agent: str
) -> None:
    response = await client.post(f"/agents/{agent}/analyze", json=analyze_payload)
    finding = FindingBatch.model_validate(response.json()).findings[0]

    # The injection attempt survives into evidence as data ...
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in finding.evidence["raw_input_preview"]
    # ... and the agent still reports its own placeholder verdict.
    assert finding.severity.value == "info"
    assert finding.confidence == 0.0
