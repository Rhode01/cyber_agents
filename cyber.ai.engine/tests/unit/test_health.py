"""Health endpoint tests."""

from __future__ import annotations

from httpx import AsyncClient

from tests.conftest import AGENTS


async def test_health_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "ai.engine"
    assert set(body["agents"]) == set(AGENTS)


async def test_health_never_leaks_the_api_key(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert "api_key" not in response.text
    assert "openai_api_key" not in response.text


async def test_openapi_mounts_one_route_per_agent(client: AsyncClient) -> None:
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    for agent in AGENTS:
        assert f"/agents/{agent}/analyze" in paths
