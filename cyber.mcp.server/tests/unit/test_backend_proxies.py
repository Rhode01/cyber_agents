"""The tools that proxy the backend REST API.

These exist because nothing previously exercised them: all four called
``/api/v1/...``, a prefix the backend does not mount, so every one returned 404 in
production while the test suite stayed green. Each test below asserts the path
that was actually requested.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from app import server


@pytest.fixture
def recorded() -> Iterator[list[httpx.Request]]:
    """Install a mock backend and record every request the tools make."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/summary"):
            return httpx.Response(200, json={"asset": "10.0.0.5", "count": 2, "severities": {}})
        if request.url.path.startswith("/agents/"):
            return httpx.Response(200, json={"agent": "vulnerability", "mode": "inline"})
        if request.url.path == "/findings":
            return httpx.Response(200, json={"items": [], "total": 0, "limit": 50, "offset": 0})
        return httpx.Response(200, json={"id": "f1"})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://backend.test"
    )
    previous = server.http_client
    server.http_client = client
    try:
        yield requests
    finally:
        server.http_client = previous


def _paths(requests: list[httpx.Request]) -> list[str]:
    return [request.url.path for request in requests]


async def test_list_findings_uses_the_unprefixed_backend_path(
    recorded: list[httpx.Request],
) -> None:
    await server.list_findings()

    assert _paths(recorded) == ["/findings"]


async def test_the_findings_limit_is_clamped_to_the_backend_maximum(
    recorded: list[httpx.Request],
) -> None:
    """The backend answers 422 above 200, so an unbounded limit served nothing."""
    await server.list_findings(limit=10_000)

    assert recorded[0].url.params["limit"] == str(server.MAX_FINDINGS_LIMIT)


async def test_the_findings_limit_has_a_floor(recorded: list[httpx.Request]) -> None:
    await server.list_findings(limit=0)

    assert recorded[0].url.params["limit"] == "1"


async def test_filters_are_passed_through(recorded: list[httpx.Request]) -> None:
    await server.list_findings(agent="vulnerability", severity="high")

    params = recorded[0].url.params
    assert params["agent"] == "vulnerability"
    assert params["severity"] == "high"


async def test_get_finding_uses_the_unprefixed_backend_path(
    recorded: list[httpx.Request],
) -> None:
    await server.get_finding("abc-123")

    assert _paths(recorded) == ["/findings/abc-123"]


async def test_summarize_delegates_to_the_backends_own_summary(
    recorded: list[httpx.Request],
) -> None:
    """Tallying a page of results client-side under-counted past the page size."""
    result = await server.summarize_findings("10.0.0.5")

    assert _paths(recorded) == ["/findings/summary"]
    assert recorded[0].url.params["asset"] == "10.0.0.5"
    assert result["count"] == 2


async def test_run_agent_uses_the_unprefixed_backend_path(
    recorded: list[httpx.Request],
) -> None:
    await server.run_agent(agent="vulnerability", source="nmap", raw_input="x")

    assert _paths(recorded) == ["/agents/vulnerability/run"]


async def test_run_agent_rejects_an_unknown_agent(recorded: list[httpx.Request]) -> None:
    result = await server.run_agent(agent="not-an-agent", source="nmap", raw_input="x")

    assert result["status_code"] == 400
    assert recorded == [], "an unknown agent must not reach the backend"


async def test_exposure_reports_known_findings_from_the_backend(
    recorded: list[httpx.Request],
) -> None:
    result = await server.lookup_asset_exposure("10.0.0.5")

    assert result["exposure"] == "internal"
    assert result["known_findings"]["available"] is True
    assert result["known_findings"]["count"] == 2
    assert _paths(recorded) == ["/findings/summary"]


# --------------------------------------------------------- backend down --


@pytest.fixture
def unreachable() -> Iterator[None]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nothing listening")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://backend.test"
    )
    previous = server.http_client
    server.http_client = client
    try:
        yield
    finally:
        server.http_client = previous


async def test_an_unreachable_backend_is_reported_as_data(unreachable: None) -> None:
    """A tool result an agent can reason about, not an exploding tool call."""
    del unreachable
    result: dict[str, Any] = await server.list_findings()

    assert "could not be reached" in result["error"]


async def test_exposure_still_classifies_when_the_backend_is_down(
    unreachable: None,
) -> None:
    """Classification is local; only the known-findings lookup needs the backend."""
    del unreachable
    result = await server.lookup_asset_exposure("8.8.8.8")

    assert result["exposure"] == "internet"
    assert result["known_findings"]["available"] is False


# --------------------------------------------------------- scan refusal --


async def test_a_scan_outside_the_allowlist_never_starts_the_scanner() -> None:
    """No backend or subprocess involved: the guard runs first."""
    result = await server.nmap_service_scan("8.8.8.8")

    assert result["ok"] is False
    assert result["meta"]["refused"] is True
    assert "allowlist" in result["error"]


async def test_a_malformed_port_specification_never_starts_the_scanner() -> None:
    result = await server.nmap_service_scan("127.0.0.1", ports="-oA/tmp/pwned")

    assert result["ok"] is False
    assert result["meta"]["refused"] is True
