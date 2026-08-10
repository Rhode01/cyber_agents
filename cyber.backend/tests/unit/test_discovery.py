"""Discovery endpoint tests.

The endpoint is a thin proxy over the ai.engine client, so the ai.engine client
dependency is swapped for a fixture that answers without any network.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from cyber_contracts import DiscoveryReport
from httpx import AsyncClient

from app.api.deps import get_ai_engine_client
from app.main import app


@pytest.fixture
def fake_report() -> DiscoveryReport:
    return DiscoveryReport(
        interfaces=[{"name": "eth0", "ip": "10.0.0.5", "prefix": 24, "subnet": "10.0.0.0/24"}],
        subnets=["10.0.0.0/24"],
        live_hosts=["10.0.0.1", "10.0.0.20"],
        web_hosts=[{"host": "10.0.0.20", "ports": [80], "urls": ["http://10.0.0.20"]}],
        duration_seconds=1.5,
        notes=[],
    )


class _FakeClient:
    def __init__(self, report: DiscoveryReport) -> None:
        self._report = report

    async def run_discovery(self) -> DiscoveryReport:
        return self._report

    async def aclose(self) -> None:
        return None


async def test_discovery_run_returns_the_report(
    client: AsyncClient, fake_report: DiscoveryReport
) -> None:
    async def fake_dep() -> AsyncIterator[Any]:
        yield _FakeClient(fake_report)

    app.dependency_overrides[get_ai_engine_client] = fake_dep
    try:
        response = await client.post("/discovery/run")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["subnets"] == ["10.0.0.0/24"]
    assert body["web_hosts"][0]["host"] == "10.0.0.20"
    assert body["web_hosts"][0]["urls"] == ["http://10.0.0.20"]
