"""The stub MCP server imports, registers its tool, and serves MCP plus health.

``StreamableHTTPSessionManager.run()`` may be entered only once per instance, so
every HTTP test shares one module-scoped client and therefore one lifespan. Two
``with TestClient(app)`` blocks in the same module would fail on the second.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from mcpserver.config import Settings
from mcpserver.server import MCP_ENDPOINT, app, describe_platform, mcp, mcp_app


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """One client, one lifespan, for every HTTP test in this module.

    base_url matters: the MCP transport rejects unknown Host headers as
    DNS-rebinding protection, and TestClient's default is "testserver".
    """
    with TestClient(app, base_url=f"http://localhost:{Settings().mcp_port}") as test_client:
        yield test_client


def test_server_is_named_from_settings() -> None:
    assert mcp.name == Settings().mcp_server_name


async def test_all_tools_are_registered() -> None:
    tools = await mcp.list_tools()
    names = {tool.name for tool in tools}

    assert "describe_platform" in names
    assert "list_findings" in names
    assert "get_finding" in names
    assert "summarize_findings" in names
    assert "run_agent" in names


async def test_describe_platform_lists_every_agent() -> None:
    described = await describe_platform()

    assert described["phase"] == 2
    assert set(described["agents"]) == {"vulnerability", "phishing", "network", "webapp"}


def test_mcp_app_serves_its_endpoint_where_health_advertises_it() -> None:
    """Guards the mount point: the MCP app owns /mcp, so it mounts at /.

    Inspects the single shared ``mcp_app`` rather than calling the factory again,
    which would build a second session manager the lifespan does not run.
    """
    paths = {getattr(route, "path", None) for route in mcp_app.routes}

    assert MCP_ENDPOINT in paths


def test_health_endpoint_serves_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "mcpserver"
    assert body["mcp_endpoint"] == MCP_ENDPOINT


def test_mcp_endpoint_completes_an_initialize_handshake(client: TestClient) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }

    response = client.post(
        MCP_ENDPOINT,
        json=request,
        headers={"accept": "application/json, text/event-stream"},
    )

    assert response.status_code == 200
    assert "serverInfo" in response.text
