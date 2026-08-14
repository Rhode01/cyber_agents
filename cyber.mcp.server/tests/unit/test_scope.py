"""Operator-managed scan scope, fetched from the backend.

The property under test throughout is the direction of failure. Every way this
fetch can go wrong - unreachable, 500, 401, malformed body, an unreadable entry -
must leave scope *narrower*, never wider. A refused scan is visible and
recoverable; an unauthorised one is neither.
"""

from __future__ import annotations

import httpx
import pytest

from app.tools import parse_networks
from app.tools.scope import SCOPE_NETWORKS_PATH, fetch_scope_networks


def _client(handler: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        base_url="http://backend.test",
    )


async def test_active_scope_is_returned_as_networks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == SCOPE_NETWORKS_PATH
        return httpx.Response(200, json={"networks": ["156.38.162.98/32", "203.0.113.0/24"]})

    networks = await fetch_scope_networks(_client(handler), request_timeout=1.0)

    assert [str(n) for n in networks] == ["156.38.162.98/32", "203.0.113.0/24"]


@pytest.mark.parametrize(
    "handler_name",
    ["unreachable", "server_error", "unauthorized", "not_json", "wrong_shape"],
)
async def test_every_failure_mode_narrows_scope(handler_name: str) -> None:
    """None of these may return networks - the configured allowlist stands alone."""

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("backend is down")

    def server_error(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    def unauthorized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "key required"})

    def not_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>a proxy error page</html>")

    def wrong_shape(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"networks": "203.0.113.0/24"})

    handler = locals()[handler_name]

    assert await fetch_scope_networks(_client(handler), request_timeout=1.0) == []


async def test_an_unreadable_entry_is_dropped_not_fatal() -> None:
    """One bad row must not take the whole allowlist with it."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"networks": ["156.38.162.98/32", "not-a-cidr", "10.0.0.0/8"]}
        )

    networks = await fetch_scope_networks(_client(handler), request_timeout=1.0)

    assert [str(n) for n in networks] == ["156.38.162.98/32", "10.0.0.0/8"]


async def test_scope_adds_to_the_configured_list_rather_than_replacing_it() -> None:
    """The union is what the scan check sees.

    Config holds what is true of the deployment; the backend holds what an
    operator authorised. Neither may erase the other.
    """
    configured = parse_networks(["127.0.0.0/8", "10.0.0.0/8"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"networks": ["156.38.162.98/32"]})

    fetched = await fetch_scope_networks(_client(handler), request_timeout=1.0)
    combined = [str(n) for n in (*configured, *fetched)]

    assert combined == ["127.0.0.0/8", "10.0.0.0/8", "156.38.162.98/32"]
