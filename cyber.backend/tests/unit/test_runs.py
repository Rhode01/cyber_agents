"""Runs endpoint tests.

The runs table lives in PostgreSQL, so these exercise the real round trip and
are skipped unless ``RUN_INTEGRATION_TESTS=1`` (matching the rest of the
backend's DB-backed tests).
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient

from tests.conftest import requires_database

pytestmark = requires_database


async def test_run_lifecycle(client: AsyncClient) -> None:
    created = await client.post(
        "/runs", json={"target": "http://localhost:8081", "mode": "auto"}
    )
    assert created.status_code == 201
    body = created.json()
    assert body["target"] == "http://localhost:8081"
    assert body["mode"] == "auto"
    assert body["status"] == "running"
    assert body["agent_statuses"] == {}
    run_id = body["id"]
    uuid.UUID(run_id)

    updated = await client.patch(
        f"/runs/{run_id}",
        json={
            "status": "completed",
            "agent_statuses": {
                "webapp": {"state": "done", "findings": 3},
                "phishing": {"state": "skipped", "findings": 0},
            },
            "discovery": {"subnets": ["10.0.0.0/24"], "live_hosts": ["10.0.0.1"]},
        },
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["status"] == "completed"
    assert body["agent_statuses"]["webapp"]["findings"] == 3
    assert body["discovery"]["live_hosts"] == ["10.0.0.1"]
    assert body["finished_at"] is not None

    fetched = await client.get(f"/runs/{run_id}")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "completed"

    latest = await client.get("/runs/latest")
    assert latest.status_code == 200
    assert latest.json()["id"] == run_id


async def test_run_requires_a_target(client: AsyncClient) -> None:
    response = await client.post("/runs", json={"mode": "manual"})
    assert response.status_code == 422
