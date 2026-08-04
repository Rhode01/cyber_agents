"""MCP server - Phase 1 stub.

Starts, registers one trivial tool, and logs. The MCP ASGI app is mounted at the
root of a small Starlette app that also serves ``GET /health``, so the container
has something real to health-check. The MCP app puts its own endpoint at
``/mcp``, which is why it is mounted at ``/`` and not at ``/mcp``.

Run it either way:

    uvicorn mcpserver.server:app --host 0.0.0.0 --port 8004     # Streamable HTTP
    python -m mcpserver.server                                  # stdio

Real tools - handing findings, scan triggers, and asset lookups to an MCP host -
are deferred past Phase 1.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from mcpserver import __version__
from mcpserver.config import get_settings

logger = logging.getLogger("mcpserver")

settings = get_settings()

# Where the MCP ASGI app exposes its own endpoint once mounted at "/".
MCP_ENDPOINT = "/mcp"

mcp = MCPServer(settings.mcp_server_name)


@mcp.tool()
def describe_platform() -> dict[str, Any]:
    """Describe this platform: which detection agents exist and what phase it is in."""
    return {
        "platform": "Cybersecurity Agents Platform",
        "version": __version__,
        "phase": 1,
        "agents": ["vulnerability", "phishing", "network", "webapp"],
        "note": "Scaffolding only. No detection tools are exposed yet.",
    }


# Build the ASGI app exactly once. Each call to streamable_http_app() creates a
# fresh session manager, and the lifespan below has to run the same one the
# mounted app holds - otherwise every request fails with "Task group is not
# initialized". The manager also permits only one run() per instance.
mcp_app = mcp.streamable_http_app(
    transport_security=TransportSecuritySettings(
        allowed_hosts=settings.resolved_allowed_hosts,
        allowed_origins=settings.resolved_allowed_origins,
    )
)


async def health(request: Request) -> JSONResponse:
    """Liveness for the container healthcheck."""
    del request
    return JSONResponse(
        {
            "status": "ok",
            "service": "mcpserver",
            "version": __version__,
            "server_name": settings.mcp_server_name,
            "transport": "streamable-http",
            "mcp_endpoint": MCP_ENDPOINT,
        }
    )


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    """Run the MCP session manager for the lifetime of the ASGI app."""
    del app
    logging.basicConfig(level=getattr(logging, settings.log_level), format="%(message)s")
    logger.info("mcpserver starting: name=%s port=%s", settings.mcp_server_name, settings.mcp_port)

    async with mcp.session_manager.run():
        yield

    logger.info("mcpserver stopped")


app = Starlette(
    routes=[
        Route("/health", endpoint=health, methods=["GET"]),
        Mount("/", app=mcp_app),
    ],
    lifespan=lifespan,
)


def main() -> None:
    """Run over stdio, for an MCP host that launches this as a subprocess."""
    logging.basicConfig(level=getattr(logging, settings.log_level), format="%(message)s")
    logger.info("mcpserver starting on stdio: name=%s", settings.mcp_server_name)
    mcp.run()


if __name__ == "__main__":
    main()
