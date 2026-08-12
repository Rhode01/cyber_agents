"""MCP client: how agents reach their tools.

The ai.engine reasons; the MCP server executes. Every scanner and lookup an agent
uses comes through here, over Streamable HTTP, authenticated with the internal
key.

Three properties this module exists to guarantee:

**It degrades instead of failing.** An unreachable MCP server, a 401, a tool that
times out - all of them come back as a result the caller can read. The
deterministic rule engine produces findings without any enrichment at all, so a
tool outage should cost detail, never the whole assessment.

**Tools are allowlisted, not mirrored.** ``ALLOWED_TOOLS`` is deliberately not
"whatever ``list_tools`` returned". The MCP server also exposes ``run_agent``,
which calls the backend, which calls back into this service - handing that to an
agent gives it a tool that re-invokes itself. Enumerating what we want is the
difference between a toolset and a recursion.

**One session per assessment.** ``mcp.Client`` is single-use: ``__aenter__``
guards on an ``_entered`` flag that ``__aexit__`` never clears, and the transport
context manager is built once at construction. So a session cannot be cached and
re-entered; it is opened once per agent run, used for every call that run makes,
and closed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

import httpx2
from cyber_contracts import INTERNAL_KEY_HEADER
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

NMAP_SCAN_TOOL: Final = "nmap_service_scan"
CVE_LOOKUP_TOOL: Final = "lookup_cve"
ASSET_EXPOSURE_TOOL: Final = "lookup_asset_exposure"

# Phishing enrichment. These keep the ai.engine free of egress: it already holds no
# database, and routing DNS, RDAP and the link fetch through MCP means the network boundary
# lives in one service, next to the address policy that governs it.
DNS_RECORDS_TOOL: Final = "dns_records"
DOMAIN_AGE_TOOL: Final = "lookup_domain_age"
FETCH_URL_TOOL: Final = "fetch_url"

ALLOWED_TOOLS: Final = frozenset(
    {
        NMAP_SCAN_TOOL,
        CVE_LOOKUP_TOOL,
        ASSET_EXPOSURE_TOOL,
        DNS_RECORDS_TOOL,
        DOMAIN_AGE_TOOL,
        FETCH_URL_TOOL,
    }
)
"""The only tools an agent may call. See the module docstring on why not all."""


def _unavailable(tool: str, detail: str) -> dict[str, Any]:
    """The shape a failed tool call returns.

    Mirrors the MCP server's own failure shape so a caller does not have to tell
    "the tool ran and failed" apart from "the tool never ran".
    """
    return {"ok": False, "tool": tool, "output": "", "error": detail, "meta": {"available": False}}


class McpTools:
    """Tool calls for one agent run, over one live MCP session."""

    def __init__(self, session: ClientSession, *, available: frozenset[str]) -> None:
        self._session = session
        self._available = available

    @property
    def available(self) -> frozenset[str]:
        """Allowlisted tools this server actually offers."""
        return self._available

    def has(self, tool: str) -> bool:
        return tool in self._available

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one tool, returning its structured result or a readable failure."""
        if tool not in ALLOWED_TOOLS:
            return _unavailable(tool, f"{tool!r} is not in this client's allowlist.")
        if tool not in self._available:
            return _unavailable(tool, f"The MCP server does not offer {tool!r}.")

        try:
            result = await self._session.call_tool(tool, arguments)
        except Exception as exc:
            logger.warning("mcp.call_failed", tool=tool, error=str(exc))
            return _unavailable(tool, f"The tool call failed: {exc}")

        payload = getattr(result, "structured_content", None)
        if isinstance(payload, dict):
            # MCPServer wraps a dict-returning tool as {"result": {...}}; unwrap
            # so callers see what the tool actually returned.
            inner = payload.get("result")
            return inner if isinstance(inner, dict) else payload

        text = _text_of(result)
        if getattr(result, "is_error", False):
            return _unavailable(tool, text or "The tool reported an error with no detail.")
        return {"ok": True, "tool": tool, "output": text, "error": "", "meta": {}}


def _text_of(result: object) -> str:
    """Concatenate the text blocks of a tool result."""
    blocks = getattr(result, "content", None)
    if not isinstance(blocks, list):
        return ""
    return "\n".join(
        str(block.text) for block in blocks if getattr(block, "type", None) == "text"
    )


@asynccontextmanager
async def open_tools(settings: Settings | None = None) -> AsyncIterator[McpTools | None]:
    """Open an MCP session for one agent run.

    Yields ``None`` when the server is unreachable or rejects the handshake, so
    the caller's happy path and degraded path are the same code with one guard.
    """
    resolved = settings or get_settings()

    headers = {"accept": "application/json"}
    if resolved.internal_key:
        headers[INTERNAL_KEY_HEADER] = resolved.internal_key

    try:
        # The transport does not own a client we hand it, so this context manager
        # owns closing it - hence the explicit nesting rather than a bare client.
        async with httpx2.AsyncClient(
            headers=headers,
            follow_redirects=True,
            timeout=httpx2.Timeout(resolved.mcp_timeout_seconds),
        ) as http_client:
            async with streamable_http_client(
                resolved.mcp_server_url, http_client=http_client
            ) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=resolved.mcp_timeout_seconds,
                ) as session:
                    await session.initialize()
                    available = await _discover(session)
                    logger.info(
                        "mcp.session.open",
                        url=resolved.mcp_server_url,
                        tools=sorted(available),
                    )
                    yield McpTools(session, available=available)
    except Exception as exc:
        logger.warning(
            "mcp.session.unavailable",
            url=resolved.mcp_server_url,
            error=_root_cause(exc),
            hint=(
                "Agents fall back to deterministic rules with no enrichment. Check "
                "MCP_SERVER_URL, INTERNAL_KEY, and MCP_ALLOWED_HOSTS (a Host the "
                "transport does not recognise answers 421)."
            ),
        )
        yield None


def _root_cause(exc: BaseException) -> str:
    """Describe the innermost failure of a possibly-nested ExceptionGroup.

    The MCP transport runs inside anyio task groups, so a refused handshake
    surfaces as "unhandled errors in a TaskGroup (1 sub-exception)" - which names
    every failure mode identically and is exactly the wrong message when the real
    cause is a 401 or a 421 Host rejection.
    """
    current: BaseException = exc
    seen = 0
    while isinstance(current, BaseExceptionGroup) and current.exceptions and seen < 10:
        current = current.exceptions[0]
        seen += 1
    return f"{type(current).__name__}: {current}"


async def _discover(session: ClientSession) -> frozenset[str]:
    """Which allowlisted tools does this server offer?"""
    listing = await session.list_tools()
    offered = {tool.name for tool in listing.tools}
    missing = ALLOWED_TOOLS - offered
    if missing:
        logger.warning("mcp.tools.missing", missing=sorted(missing))
    return frozenset(offered & ALLOWED_TOOLS)
