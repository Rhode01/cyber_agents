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


async def test_openapi_exposes_every_route(client: AsyncClient) -> None:
    """The full route surface, so a router that stops being mounted is noticed.

    This previously asserted five of about fifteen paths, which meant dropping a
    whole router from `api/v1/api.py` would not have failed anything.
    """
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]

    expected = {
        "/health",
        "/health/db",
        "/scans",
        "/scans/{scan_id}",
        "/messages",
        "/messages/url",
        "/messages/{message_id}",
        "/findings",
        "/findings/batch",
        "/findings/summary",
        "/findings/verify",
        "/findings/{finding_id}",
        "/agents/{agent}/run",
        "/runs",
        "/runs/latest",
        "/runs/status",
        "/runs/{run_id}",
        "/discovery/run",
        "/system/modules",
    }
    assert expected <= set(paths), f"missing: {sorted(expected - set(paths))}"


async def test_the_findings_summary_route_is_not_shadowed(client: AsyncClient) -> None:
    """`/findings/summary` must win over `/findings/{finding_id}`.

    FastAPI matches in registration order, so if the parameterised route were ever
    declared first, `summary` would be parsed as a finding id and 422.
    """
    response = await client.get("/openapi.json")
    paths = list(response.json()["paths"])

    assert paths.index("/findings/summary") < paths.index("/findings/{finding_id}")


@pytest.mark.integration
@requires_database
async def test_health_db_reports_a_live_connection(client: AsyncClient) -> None:
    response = await client.get("/health/db")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["driver"] == "asyncpg"
    assert body["latency_ms"] is not None
