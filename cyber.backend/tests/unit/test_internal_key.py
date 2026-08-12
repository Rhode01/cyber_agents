"""The internal-key boundary on the finding-write routes.

Two things are asserted here, and the second matters as much as the first:

* the write routes reject a caller without the key;
* the browser-facing routes do **not** require it.

Getting the second wrong locks the UI out of its own backend, which is why the
guard is applied per route rather than to the whole findings router.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from cyber_contracts import INTERNAL_KEY_HEADER, AgentKind, FindingType, Severity
from httpx import AsyncClient

from app.core.config import Settings

KEY = "backend-internal-key"


@pytest.fixture
def enforced_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Turn enforcement on for one test.

    Patched at the call site: ``get_settings`` is ``lru_cache``d and the cache
    holds a reference to the original function, so replacing the wrapped callable
    would have no effect on what the dependency sees.
    """
    configured = Settings(internal_key=KEY)
    monkeypatch.setattr("app.core.security.get_settings", lambda: configured)
    yield KEY


def _finding() -> dict[str, Any]:
    return {
        "agent": AgentKind.vulnerability.value,
        "finding_type": FindingType.outdated_service.value,
        "title": "Outdated OpenSSH",
        "description": "OpenSSH 8.9 is below the supported baseline.",
        "severity": Severity.medium.value,
        "confidence": 0.8,
        "source": "nmap",
        "asset": "10.0.0.5",
        "detected_at": datetime.now(UTC).isoformat(),
    }


async def test_posting_a_finding_without_the_key_is_rejected(
    client: AsyncClient, enforced_key: str
) -> None:
    del enforced_key
    response = await client.post("/findings", json=_finding())

    assert response.status_code == 401
    assert INTERNAL_KEY_HEADER in response.json()["detail"]


async def test_posting_a_batch_without_the_key_is_rejected(
    client: AsyncClient, enforced_key: str
) -> None:
    """This is the ai.engine push-back path; unguarded it was world-writable."""
    del enforced_key
    response = await client.post(
        "/findings/batch",
        json={"agent": AgentKind.vulnerability.value, "findings": [_finding()]},
    )

    assert response.status_code == 401


async def test_a_wrong_key_is_rejected(client: AsyncClient, enforced_key: str) -> None:
    del enforced_key
    response = await client.post(
        "/findings/batch",
        json={"agent": AgentKind.vulnerability.value, "findings": []},
        headers={INTERNAL_KEY_HEADER: "not-the-key"},
    )

    assert response.status_code == 401


async def test_the_browser_read_routes_do_not_require_the_key(
    client: AsyncClient, enforced_key: str
) -> None:
    """The frontend has no key. Guarding these would lock the UI out.

    Only a 401 is a failure here. Most of these paths need PostgreSQL, which is
    not running for unit tests, so a database error is the expected outcome - and
    it still proves the request got past the guard, which is what is being tested.
    """
    del enforced_key
    for path in ("/health", "/findings", "/findings/summary?asset=x", "/runs/status"):
        try:
            response = await client.get(path)
        except OSError:
            continue  # reached the handler, died on the database
        assert response.status_code != 401, f"{path} must stay open to the browser"


async def test_the_agent_run_route_does_not_require_the_key(
    client: AsyncClient, enforced_key: str
) -> None:
    """The Run page calls this directly from the browser."""
    del enforced_key
    response = await client.post(
        "/agents/vulnerability/run",
        json={"source": "nmap", "raw_input": "x", "background": False},
    )

    assert response.status_code != 401


# --------------------------------------------------------------- settings --


def test_no_key_means_no_enforcement() -> None:
    """The local default. The routes stay open rather than the service refusing."""
    assert Settings(internal_key="").enforce_internal_key is False


def test_a_key_turns_enforcement_on() -> None:
    assert Settings(internal_key=KEY).enforce_internal_key is True


def test_the_backend_starts_without_a_key_even_in_production() -> None:
    """Unlike the ai.engine and MCP server, which refuse.

    The backend also serves the browser, and a backend that will not boot takes
    the whole UI with it. The routes that need protecting are guarded instead.
    """
    settings = Settings(app_env="production", internal_key="")

    assert settings.is_production is True
    assert settings.enforce_internal_key is False
