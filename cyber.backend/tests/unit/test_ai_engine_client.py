"""The ai.engine client's wire contract.

Every uploaded scan used to fail: the client posted a ``VulnerabilityAnalyzeRequest``
to ``/agents/vulnerability/analyze``, which accepts ``AnalyzeRequest`` with
``extra="forbid"``, so the ai.engine answered 422 and every scan was stored as
``failed``. Nothing caught it, because nothing asserted which path was requested.
That is what this module is for.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cyber_contracts import (
    INTERNAL_KEY_HEADER,
    AgentKind,
    FindingType,
    NormalizedScan,
    ScanFormat,
    ScanHost,
    ScanPort,
    Severity,
    VulnerabilityAnalyzeRequest,
)

from app.core.config import Settings
from app.schemas.agents import AgentRunRequest
from app.services.ai_engine.client import AiEngineClient, AiEngineError

KEY = "backend-internal-key"


def _scan() -> NormalizedScan:
    return NormalizedScan(
        format=ScanFormat.nmap_xml,
        scanner="nmap",
        scanner_version="7.94",
        hosts=[
            ScanHost(
                address="10.0.0.5",
                hostnames=["host.internal"],
                status="up",
                ports=[
                    ScanPort(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product="OpenSSH",
                        version="7.2",
                    )
                ],
            )
        ],
    )


def _finding_batch() -> dict[str, Any]:
    return {
        "agent": AgentKind.vulnerability.value,
        "findings": [
            {
                "agent": AgentKind.vulnerability.value,
                "finding_type": FindingType.known_cve.value,
                "title": "CVE-2018-15473 on 10.0.0.5:22",
                "description": "OpenSSH 7.2 is inside the affected range.",
                "severity": Severity.medium.value,
                "confidence": 0.85,
                "source": "nmap",
                "asset": "10.0.0.5",
                "port": 22,
                "service": "ssh",
                "cve_ids": ["CVE-2018-15473"],
                "detected_at": datetime.now(UTC).isoformat(),
            }
        ],
    }


@pytest.fixture
def recorded() -> Iterator[tuple[AiEngineClient, list[httpx.Request]]]:
    """A client whose transport records requests and returns a valid batch."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=_finding_batch())

    client = AiEngineClient(Settings(internal_key=KEY))
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://ai-engine.test",
        headers={"accept": "application/json", INTERNAL_KEY_HEADER: KEY},
    )
    yield client, requests


async def test_a_parsed_scan_goes_to_the_assess_route(
    recorded: tuple[AiEngineClient, list[httpx.Request]],
) -> None:
    """Not /analyze, which forbids the extra fields and answered 422."""
    client, requests = recorded
    request = VulnerabilityAnalyzeRequest(
        scan_id=uuid4(), source="nmap", asset="10.0.0.5", scan=_scan(), context={}
    )

    batch = await client.assess_vulnerability(request)

    assert [r.url.path for r in requests] == ["/agents/vulnerability/assess"]
    assert requests[0].method == "POST"
    assert len(batch.findings) == 1
    await client.aclose()


async def test_the_assess_body_carries_the_whole_parsed_scan(
    recorded: tuple[AiEngineClient, list[httpx.Request]],
) -> None:
    client, requests = recorded
    scan_id = uuid4()
    request = VulnerabilityAnalyzeRequest(
        scan_id=scan_id,
        source="nmap",
        asset="10.0.0.5",
        scan=_scan(),
        context={"filename": "s.xml"},
    )

    await client.assess_vulnerability(request)

    body = requests[0].read().decode()
    assert str(scan_id) in body
    assert '"version":"7.2"' in body.replace(" ", "")
    await client.aclose()


async def test_the_generic_analyze_route_is_still_used_for_raw_artifacts(
    recorded: tuple[AiEngineClient, list[httpx.Request]],
) -> None:
    client, requests = recorded

    await client.analyze(
        AgentKind.vulnerability,
        AgentRunRequest(source="nmap", raw_input="22/tcp open ssh", asset="10.0.0.5"),
    )

    assert [r.url.path for r in requests] == ["/agents/vulnerability/analyze"]
    await client.aclose()


async def test_the_internal_key_is_sent_on_every_request() -> None:
    """As a default header on the client, so a new method cannot forget it."""
    client = AiEngineClient(Settings(internal_key=KEY))
    try:
        assert client._client.headers[INTERNAL_KEY_HEADER] == KEY
    finally:
        await client.aclose()


async def test_no_key_header_is_sent_when_none_is_configured() -> None:
    """An empty header would be worse than none: it reads as a real attempt."""
    client = AiEngineClient(Settings(internal_key=""))
    try:
        assert INTERNAL_KEY_HEADER not in client._client.headers
    finally:
        await client.aclose()


async def test_an_upstream_error_carries_its_status_code() -> None:
    """So analyze_scan can put "(upstream status 401)" in the scan's error."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "nope"})

    client = AiEngineClient(Settings(internal_key=KEY))
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://ai-engine.test"
    )
    try:
        with pytest.raises(AiEngineError) as err:
            await client.assess_vulnerability(
                VulnerabilityAnalyzeRequest(
                    scan_id=uuid4(), source="nmap", scan=_scan(), context={}
                )
            )
        assert err.value.status_code == 401
    finally:
        await client.aclose()


async def test_a_response_that_breaks_the_finding_contract_is_rejected() -> None:
    """Better a failed scan with a reason than findings nobody validated."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"agent": "vulnerability", "unexpected": True})

    client = AiEngineClient(Settings(internal_key=KEY))
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://ai-engine.test"
    )
    try:
        with pytest.raises(AiEngineError, match="breaks the Finding contract"):
            await client.assess_vulnerability(
                VulnerabilityAnalyzeRequest(
                    scan_id=uuid4(), source="nmap", scan=_scan(), context={}
                )
            )
    finally:
        await client.aclose()
