"""Health endpoint tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import requires_database


async def test_health_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "backend"
    assert body["version"]


async def test_openapi_exposes_every_phase_one_route(client: AsyncClient) -> None:
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/health" in paths
    assert "/health/db" in paths
    assert "/findings" in paths
    assert "/findings/{finding_id}" in paths
    assert "/agents/{agent}/run" in paths


@pytest.mark.integration
@requires_database
async def test_health_db_reports_a_live_connection(client: AsyncClient) -> None:
    response = await client.get("/health/db")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["driver"] == "asyncpg"
    assert body["latency_ms"] is not None
