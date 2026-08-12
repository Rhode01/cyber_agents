"""The internal-key middleware.

Deliberately built against a bare Starlette app rather than ``app.server.app``:
the MCP session manager may be entered only once per process, and
``test_server.py`` already owns that single entry. Exercising the middleware in
isolation also keeps these tests about authentication rather than about MCP.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.config import Settings
from app.security import INTERNAL_KEY_HEADER, InternalKeyMiddleware, matches_internal_key

KEY = "an-internal-key"


async def _ok(request: Request) -> JSONResponse:
    del request
    return JSONResponse({"status": "ok"})


def _app(*, expected_key: str, enforce: bool) -> Starlette:
    return Starlette(
        routes=[
            Route("/health", endpoint=_ok, methods=["GET"]),
            Route("/mcp", endpoint=_ok, methods=["GET", "POST"]),
        ],
        middleware=[
            Middleware(InternalKeyMiddleware, expected_key=expected_key, enforce=enforce)
        ],
    )


# ------------------------------------------------------------ comparison --


@pytest.mark.parametrize(
    ("presented", "expected", "result"),
    [
        (KEY, KEY, True),
        ("wrong", KEY, False),
        ("", KEY, False),
        (None, KEY, False),
        # An unconfigured service must not accept every caller by matching blanks.
        ("", "", False),
        (None, "", False),
        (KEY, "", False),
        # Non-ASCII header values must not raise.
        ("ключ", KEY, False),
    ],
)
def test_key_comparison(presented: str | None, expected: str, result: bool) -> None:
    assert matches_internal_key(presented, expected) is result


# ----------------------------------------------------------- enforcement --


def test_the_mcp_endpoint_is_rejected_without_a_key() -> None:
    with TestClient(_app(expected_key=KEY, enforce=True)) as client:
        response = client.post("/mcp", json={})

    assert response.status_code == 401
    assert INTERNAL_KEY_HEADER in response.json()["detail"]


def test_the_mcp_endpoint_is_rejected_with_the_wrong_key() -> None:
    with TestClient(_app(expected_key=KEY, enforce=True)) as client:
        response = client.post("/mcp", json={}, headers={INTERNAL_KEY_HEADER: "nope"})

    assert response.status_code == 401


def test_the_mcp_endpoint_accepts_the_configured_key() -> None:
    with TestClient(_app(expected_key=KEY, enforce=True)) as client:
        response = client.post("/mcp", json={}, headers={INTERNAL_KEY_HEADER: KEY})

    assert response.status_code == 200


def test_health_stays_open_while_enforcing() -> None:
    """The container healthcheck has no key; locking it out reads as unhealthy."""
    with TestClient(_app(expected_key=KEY, enforce=True)) as client:
        response = client.get("/health")

    assert response.status_code == 200


def test_nothing_is_enforced_when_enforcement_is_off() -> None:
    with TestClient(_app(expected_key="", enforce=False)) as client:
        assert client.post("/mcp", json={}).status_code == 200
        assert client.get("/health").status_code == 200


# --------------------------------------------------------------- settings --


def test_a_non_local_env_refuses_to_start_without_a_key() -> None:
    """Fail closed: the MCP endpoint exposes scan and agent-run tools."""
    with pytest.raises(ValueError, match="INTERNAL_KEY must be set"):
        Settings(app_env="production", internal_key="")


def test_a_key_turns_enforcement_on_even_locally() -> None:
    """So the production path can be exercised before it is deployed."""
    assert Settings(app_env="local", internal_key=KEY).enforce_internal_key is True


def test_local_without_a_key_does_not_enforce() -> None:
    assert Settings(app_env="local", internal_key="").enforce_internal_key is False


# -------------------------------------------------------- allowed hosts --


def test_the_compose_service_name_is_an_allowed_host() -> None:
    """Other containers reach this service as "mcpserver:8004".

    A Host the transport does not recognise is answered with 421 Misdirected
    Request, which names no cause - so this is asserted rather than assumed.
    """
    hosts = Settings(app_env="local", internal_key=KEY, mcp_port=8004).resolved_allowed_hosts

    assert "mcpserver" in hosts
    assert "mcpserver:8004" in hosts
    assert "localhost:8004" in hosts


def test_an_explicit_allowlist_replaces_the_default() -> None:
    settings = Settings(
        app_env="local", internal_key=KEY, mcp_allowed_hosts=["mcp.example.test"]
    )

    assert settings.resolved_allowed_hosts == ["mcp.example.test"]
