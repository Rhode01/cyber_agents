"""MCP server - Phase 2.

Exposes platform capabilities to MCP clients via standard HTTP calls to the backend.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
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

MCP_ENDPOINT = "/mcp"

mcp = MCPServer(settings.mcp_server_name)

# Global client initialized in lifespan
http_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    """Return the global HTTP client."""
    if http_client is None:
        raise RuntimeError("HTTP client is not initialized")
    return http_client


@mcp.tool()
async def describe_platform() -> dict[str, Any]:
    """Describe this platform: which detection agents exist and what phase it is in."""
    return {
        "platform": "Cybersecurity Agents Platform",
        "version": __version__,
        "phase": 2,
        "agents": ["vulnerability", "phishing", "network", "webapp"],
        "note": "Fully functional. Exposes findings and scan triggers.",
    }


@mcp.tool()
async def list_findings(
    agent: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List findings from the platform backend."""
    client = get_client()
    params: dict[str, str | int] = {"limit": limit}
    if agent:
        params["agent"] = agent
    if severity:
        params["severity"] = severity

    resp = await client.get("/api/v1/findings", params=params)
    if resp.is_error:
        return {"error": resp.text, "status_code": resp.status_code}
    return resp.json()  # type: ignore[no-any-return]


@mcp.tool()
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Retrieve a single finding by its UUID."""
    client = get_client()
    resp = await client.get(f"/api/v1/findings/{finding_id}")
    if resp.is_error:
        return {"error": resp.text, "status_code": resp.status_code}
    return resp.json()  # type: ignore[no-any-return]


@mcp.tool()
async def summarize_findings(asset: str) -> dict[str, Any]:
    """Summarize all active findings for a specific asset (IP, hostname, etc.)."""
    client = get_client()
    # Fetch all findings, then filter locally for the demo.
    # In a real system, the backend would support asset filtering.
    resp = await client.get("/api/v1/findings", params={"limit": 200})
    if resp.is_error:
        return {"error": resp.text, "status_code": resp.status_code}
    
    data = resp.json()
    items = data.get("items", [])
    
    # Filter by asset
    asset_findings = [f for f in items if f.get("asset") == asset]
    
    if not asset_findings:
        return {"asset": asset, "summary": "No findings found for this asset.", "count": 0}
        
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in asset_findings:
        sev = f.get("severity", "info")
        if sev in severities:
            severities[sev] += 1
            
    return {
        "asset": asset,
        "count": len(asset_findings),
        "severities": severities,
        "findings": asset_findings,
    }


@mcp.tool()
async def run_agent(
    agent: str,
    source: str,
    raw_input: str,
    asset: str | None = None,
    background: bool = False,
) -> dict[str, Any]:
    """Send an artifact to an AI engine agent for analysis.
    
    Args:
        agent: 'vulnerability', 'phishing', 'network', or 'webapp'
        source: The scanner/tool that produced the input (e.g. 'nmap', 'zap')
        raw_input: The raw text output from the scanner
        asset: Optional IP/hostname target
        background: If true, runs asynchronously via worker queue
    """
    client = get_client()
    payload = {
        "source": source,
        "raw_input": raw_input,
        "asset": asset,
        "background": background,
    }
    resp = await client.post(f"/api/v1/agents/{agent}/run", json=payload)
    if resp.is_error:
        return {"error": resp.text, "status_code": resp.status_code}
    return resp.json()  # type: ignore[no-any-return]


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
    """Run the MCP session manager and HTTP client for the lifetime of the ASGI app."""
    del app
    global http_client
    logging.basicConfig(level=getattr(logging, settings.log_level), format="%(message)s")
    logger.info("mcpserver starting: name=%s port=%s", settings.mcp_server_name, settings.mcp_port)

    http_client = httpx.AsyncClient(
        base_url=settings.backend_url,
        timeout=settings.backend_timeout_seconds,
    )

    async with mcp.session_manager.run(), http_client:
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
