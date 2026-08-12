"""Route tests for the phishing agent, including the contract that was broken.

`POST /agents/phishing/assess` did not exist until this phase. The backend's
`assess_phishing` posted to it anyway, so every uploaded message went 202 → worker → **404**
→ marked failed. Both ends were correct and nothing connected them.

The half of that contract this module pins is the request shape: `/assess` accepts a
`PhishingAnalyzeRequest` and rejects the generic `AnalyzeRequest`. The backend's
`test_message_intake.py` pins the other half. They meet in `cyber_contracts`, so neither
needs the other service running.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from cyber_contracts import (
    INTERNAL_KEY_HEADER,
    AgentKind,
    FindingBatch,
    FindingType,
    NormalizedMessage,
    PhishingAnalyzeRequest,
    Severity,
)
from httpx import ASGITransport, AsyncClient

from app.agents.common.assessment_schema import (
    ConfidenceBand,
    InjectionReport,
    InjectionSignal,
)
from app.agents.phishing.assessment_schema import PhishingAssessment, PhishingVerdict
from app.agents.phishing.assessor import ASSESSOR_CONFIG_KEY
from app.agents.phishing.indicators import Indicator
from app.agents.phishing.scoring import Score
from app.api.v1.endpoints.phishing import graph_config
from app.core.config import get_settings
from app.main import app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "messages"


def message(name: str) -> NormalizedMessage:
    return NormalizedMessage.model_validate(
        json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    )


def request_body(name: str = "phish", **overrides: Any) -> dict[str, Any]:
    payload = PhishingAnalyzeRequest(
        intake_id=uuid.uuid4(),
        source="eml-upload",
        asset="service@paypa1.com",
        message=message(name),
        context={"filename": f"email-{name}.eml"},
    )
    body = payload.model_dump(mode="json")
    body.update(overrides)
    return body


async def fake_assessor(
    indicators: Sequence[Indicator],
    score: Score,
    *,
    source: str,
    asset: str | None,
    body_excerpt: str,
    enrichment: dict[str, Any] | None,
    context: dict[str, Any],
) -> PhishingAssessment:
    del score, source, asset, body_excerpt, enrichment, context
    return PhishingAssessment(
        injection=InjectionReport(signal=InjectionSignal.none, note="none seen"),
        key_indicator_ids=[indicator.indicator_id for indicator in indicators],
        explanation="The sending domain imitates PayPal and the link goes to a bare address.",
        verdict=PhishingVerdict.phishing,
        severity="high",
        confidence=ConfidenceBand.high,
        title="Credential phishing impersonating PayPal",
        recommendation="Block the sender and delete the message.",
    )


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """A client that injects the fake assessor through the router's config dependency.

    Overriding `graph_config` is how the seam reaches through HTTP. The default returns an
    empty dict, so production gets the real assessor - a test that passed because
    production had silently substituted a fake is the failure that design prevents.
    """
    app.dependency_overrides[graph_config] = lambda: {
        "configurable": {ASSESSOR_CONFIG_KEY: fake_assessor}
    }
    settings = get_settings()
    headers = {INTERNAL_KEY_HEADER: settings.internal_key} if settings.internal_key else {}
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://ai-engine.test", headers=headers
    ) as http_client:
        yield http_client
    app.dependency_overrides.pop(graph_config, None)


# ---------------------------------------------------------------------------
# /assess - the real path
# ---------------------------------------------------------------------------


async def test_assess_accepts_a_parsed_message_and_returns_findings(
    client: AsyncClient,
) -> None:
    response = await client.post("/agents/phishing/assess", json=request_body())

    assert response.status_code == 200

    # Validated against the model the backend uses, extra="forbid" included.
    batch = FindingBatch.model_validate(response.json())
    assert batch.agent is AgentKind.phishing
    assert batch.findings

    primary = batch.findings[0]
    assert primary.finding_type is FindingType.phishing_message
    assert primary.severity is not Severity.info
    assert primary.description
    assert primary.recommendation


async def test_assess_rejects_the_generic_analyze_shape(client: AsyncClient) -> None:
    """The 404-shaped bug, pinned from this side.

    `AnalyzeRequest` cannot carry a parsed message, and `PhishingAnalyzeRequest` forbids
    extra fields - so posting the old shape must 422 rather than half-work.
    """
    response = await client.post(
        "/agents/phishing/assess",
        json={"source": "nmap", "asset": "host.example", "raw_input": "text", "context": {}},
    )

    assert response.status_code == 422


async def test_assess_rejects_unknown_fields(client: AsyncClient) -> None:
    response = await client.post(
        "/agents/phishing/assess", json=request_body(unexpected="value")
    )

    assert response.status_code == 422


async def test_a_url_submission_is_assessed_as_a_malicious_url(client: AsyncClient) -> None:
    body = request_body()
    body["message"] = {
        "format": "url",
        "sender": {"display_name": "", "address": "", "domain": ""},
        "auth": {"spf": "none", "dkim": "none", "dmarc": "none", "present": False},
        "links": [
            {
                "url": "http://45.61.188.203/paypal/login",
                "scheme": "http",
                "host": "45.61.188.203",
                "anchor_text": "",
            }
        ],
    }
    body["source"] = "url-submission"
    body["asset"] = "http://45.61.188.203/paypal/login"

    response = await client.post("/agents/phishing/assess", json=body)

    assert response.status_code == 200
    batch = FindingBatch.model_validate(response.json())
    assert batch.findings[0].finding_type is FindingType.malicious_url


async def test_clean_mail_returns_one_informational_finding(client: AsyncClient) -> None:
    """Never an empty list: "analysed, nothing found" must not look like a failure."""
    response = await client.post("/agents/phishing/assess", json=request_body("basic"))

    batch = FindingBatch.model_validate(response.json())
    assert len(batch.findings) == 1
    assert batch.findings[0].severity is Severity.info


async def test_an_injection_attempt_yields_a_second_finding(client: AsyncClient) -> None:
    response = await client.post("/agents/phishing/assess", json=request_body("injection"))

    batch = FindingBatch.model_validate(response.json())
    types = {finding.finding_type for finding in batch.findings}

    assert FindingType.prompt_injection_attempt in types
    # And the assessment it was trying to derail still happened.
    assert FindingType.phishing_message in types


async def test_the_enrichment_policy_defaults_to_not_fetching(client: AsyncClient) -> None:
    """Fetching contacts the suspect host, so an omitted policy must not enable it."""
    body = request_body()
    body.pop("enrichment", None)

    response = await client.post("/agents/phishing/assess", json=body)

    assert response.status_code == 200
    assert PhishingAnalyzeRequest.model_validate(body).enrichment.fetch_urls is False


# ---------------------------------------------------------------------------
# /analyze - superseded, but still answering clearly
# ---------------------------------------------------------------------------


async def test_analyze_still_answers_and_points_at_assess(client: AsyncClient) -> None:
    """Kept rather than removed so an existing caller gets guidance, not a 404.

    A silent empty list would be worse still - it would read as a clean result on a message
    nothing looked at.
    """
    response = await client.post(
        "/agents/phishing/analyze",
        json={"source": "nmap", "asset": "host.example", "raw_input": "text", "context": {}},
    )

    assert response.status_code == 200
    batch = FindingBatch.model_validate(response.json())
    finding = batch.findings[0]

    assert finding.finding_type is FindingType.informational
    assert finding.severity is Severity.info
    assert finding.confidence == 0.0
    assert "/assess" in finding.description
    assert "POST /messages" in finding.description
    assert "Nothing was analysed" in finding.description


# ---------------------------------------------------------------------------
# the internal key
# ---------------------------------------------------------------------------


async def test_both_routes_require_the_internal_key_when_one_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """These routes spend model budget, so they are service-to-service only."""
    from app.core import security

    key = "test-internal-key"
    monkeypatch.setattr(security, "get_settings", lambda: _settings_with_key(key))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://ai-engine.test") as bare:
        for path in ("/agents/phishing/assess", "/agents/phishing/analyze"):
            response = await bare.post(path, json={})
            assert response.status_code == 401, path
            assert INTERNAL_KEY_HEADER in response.json()["detail"]


def _settings_with_key(key: str) -> Any:
    from app.core.config import Settings

    return Settings(**{**get_settings().model_dump(), "internal_key": key})
