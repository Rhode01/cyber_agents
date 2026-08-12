"""The ``/assess`` route and the internal-key boundary.

``/assess`` exists because ``AnalyzeRequest`` forbids extra fields, so the
backend's parsed-scan payload could not be sent to ``/analyze``: every uploaded
scan answered 422. These tests pin the shape that fixes it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
from cyber_contracts import FindingBatch, FindingType, Severity
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.main import app


def _scan_payload(**overrides: Any) -> dict[str, Any]:
    """A ``VulnerabilityAnalyzeRequest`` body, as the backend sends it."""
    payload: dict[str, Any] = {
        "scan_id": str(uuid4()),
        "source": "nmap",
        "asset": "10.10.1.20",
        "scan": {
            "format": "nmap_xml",
            "scanner": "nmap",
            "scanner_version": "7.94",
            "started_at": None,
            "hosts": [
                {
                    "address": "10.10.1.20",
                    "hostnames": ["server01.internal"],
                    "status": "up",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "product": "OpenSSH",
                            "version": "7.2",
                            "extrainfo": "protocol 2.0",
                            "cpe": ["cpe:/a:openbsd:openssh:7.2"],
                        }
                    ],
                }
            ],
        },
        "context": {"filename": "scan.xml"},
    }
    payload.update(overrides)
    return payload


async def test_a_parsed_scan_is_assessed(client: AsyncClient) -> None:
    response = await client.post("/agents/vulnerability/assess", json=_scan_payload())

    assert response.status_code == 200
    batch = FindingBatch.model_validate(response.json())

    by_type = {finding.finding_type for finding in batch.findings}
    assert FindingType.outdated_service in by_type
    assert FindingType.known_cve in by_type

    cve = next(finding for finding in batch.findings if finding.cve_ids)
    assert cve.cve_ids == ["CVE-2018-15473"]
    assert cve.asset == "10.10.1.20"
    assert cve.port == 22
    assert cve.service == "ssh"
    assert cve.severity is not Severity.info


async def test_the_scan_id_is_carried_into_context(client: AsyncClient) -> None:
    """So a finding can be traced back to the intake record."""
    scan_id = str(uuid4())
    response = await client.post(
        "/agents/vulnerability/assess", json=_scan_payload(scan_id=scan_id)
    )

    assert response.status_code == 200


async def test_assess_rejects_unknown_fields(client: AsyncClient) -> None:
    response = await client.post(
        "/agents/vulnerability/assess", json={**_scan_payload(), "unexpected": "value"}
    )

    assert response.status_code == 422


async def test_analyze_still_rejects_a_parsed_scan(client: AsyncClient) -> None:
    """The reason /assess had to be a separate route rather than a wider /analyze."""
    response = await client.post("/agents/vulnerability/analyze", json=_scan_payload())

    assert response.status_code == 422


async def test_an_empty_scan_is_not_reported_as_clean(client: AsyncClient) -> None:
    payload = _scan_payload()
    payload["scan"]["hosts"] = []

    response = await client.post("/agents/vulnerability/assess", json=payload)
    batch = FindingBatch.model_validate(response.json())

    assert len(batch.findings) == 1
    assert batch.findings[0].finding_type is FindingType.informational


# ------------------------------------------------------------------ auth --


@pytest.fixture
def enforced_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Turn internal-key enforcement on for one test.

    Patched at the call site rather than on ``get_settings`` itself: it is
    ``lru_cache``d, and the cache holds a reference to the original function, so
    replacing the wrapped callable has no effect on what the cache returns.
    """
    key = "test-internal-key"
    configured = Settings(internal_key=key, app_env="local")
    monkeypatch.setattr("app.core.security.get_settings", lambda: configured)
    yield key


@pytest.fixture
async def raw_client() -> Any:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://ai-engine.test") as http_client:
        yield http_client


async def test_agent_routes_require_the_key_when_one_is_configured(
    raw_client: AsyncClient, enforced_key: str
) -> None:
    del enforced_key
    response = await raw_client.post(
        "/agents/vulnerability/analyze",
        json={"source": "nmap", "asset": "10.0.0.5", "raw_input": "x", "context": {}},
    )

    assert response.status_code == 401
    assert "X-Internal-Key" in response.json()["detail"]


async def test_agent_routes_accept_the_configured_key(
    raw_client: AsyncClient, enforced_key: str
) -> None:
    response = await raw_client.post(
        "/agents/vulnerability/analyze",
        json={"source": "nmap", "asset": "10.0.0.5", "raw_input": "x", "context": {}},
        headers={"X-Internal-Key": enforced_key},
    )

    assert response.status_code == 200


async def test_a_wrong_key_is_rejected(raw_client: AsyncClient, enforced_key: str) -> None:
    del enforced_key
    response = await raw_client.post(
        "/agents/vulnerability/analyze",
        json={"source": "nmap", "asset": "10.0.0.5", "raw_input": "x", "context": {}},
        headers={"X-Internal-Key": "not-the-key"},
    )

    assert response.status_code == 401


async def test_health_stays_open_when_the_key_is_enforced(
    raw_client: AsyncClient, enforced_key: str
) -> None:
    """The container healthcheck and the backend's module probe have no key."""
    del enforced_key
    response = await raw_client.get("/health")

    assert response.status_code == 200


async def test_discovery_requires_the_key(raw_client: AsyncClient, enforced_key: str) -> None:
    del enforced_key
    response = await raw_client.post("/discovery/run", json={})

    assert response.status_code == 401


def test_a_non_local_env_refuses_to_start_without_a_key() -> None:
    """Fail closed: a misconfigured deploy must not come up unauthenticated."""
    with pytest.raises(ValueError, match="INTERNAL_KEY must be set"):
        Settings(app_env="production", internal_key="")


def test_a_non_local_env_starts_with_a_key() -> None:
    settings = Settings(app_env="production", internal_key="a-real-key")

    assert settings.enforce_internal_key is True


def test_local_without_a_key_does_not_enforce() -> None:
    settings = Settings(app_env="local", internal_key="")

    assert settings.enforce_internal_key is False
