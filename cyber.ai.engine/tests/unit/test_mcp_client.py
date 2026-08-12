"""The MCP client's contract with the rest of the engine.

The property that matters is not that tools work - it is that the agent survives
them not working. A tool outage must cost enrichment detail, never detection.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyber_contracts import INTERNAL_KEY_HEADER

from app.agents.vulnerability import graph as vulnerability_graph
from app.agents.vulnerability.state import initial_vulnerability_state
from app.core.config import Settings
from app.mcp import ALLOWED_TOOLS, NMAP_SCAN_TOOL, McpTools, open_tools
from app.mcp.client import _root_cause, _text_of

SCANNABLE = (
    "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 7.2 (protocol 2.0)\n"
)


class _FakeSession:
    """Stands in for a live ClientSession."""

    def __init__(self, result: object = None, raises: Exception | None = None) -> None:
        self.result = result
        self.raises = raises
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> object:
        self.calls.append((name, arguments))
        if self.raises is not None:
            raise self.raises
        return self.result


class _StructuredResult:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.structured_content = payload
        self.content: list[object] = []
        self.is_error = False


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _TextResult:
    def __init__(self, text: str, *, is_error: bool = False) -> None:
        self.structured_content = None
        self.content = [_TextBlock(text)]
        self.is_error = is_error


def _tools(session: object, available: frozenset[str] = ALLOWED_TOOLS) -> McpTools:
    return McpTools(session, available=available)  # type: ignore[arg-type]


# ------------------------------------------------------------- allowlist --


async def test_run_agent_is_not_callable() -> None:
    """The MCP server exposes run_agent, which re-enters this service.

    Mirroring the server's whole toolset would hand the agent a tool that invokes
    itself. The allowlist is what stops that being a recursion.
    """
    session = _FakeSession(_StructuredResult({"result": {"ok": True}}))

    result = await _tools(session).call("run_agent", {"agent": "vulnerability"})

    assert result["ok"] is False
    assert "allowlist" in result["error"]
    assert session.calls == [], "the call must not reach the server at all"


async def test_a_tool_the_server_does_not_offer_is_reported_not_attempted() -> None:
    session = _FakeSession(_StructuredResult({"result": {"ok": True}}))

    result = await _tools(session, frozenset()).call(NMAP_SCAN_TOOL, {"target": "10.0.0.5"})

    assert result["ok"] is False
    assert "does not offer" in result["error"]
    assert session.calls == []


# ---------------------------------------------------------- result shapes --


async def test_a_dict_returning_tool_is_unwrapped() -> None:
    """MCPServer wraps a dict return as {"result": {...}}."""
    session = _FakeSession(_StructuredResult({"result": {"ok": True, "tool": "nmap"}}))

    result = await _tools(session).call(NMAP_SCAN_TOOL, {"target": "10.0.0.5"})

    assert result == {"ok": True, "tool": "nmap"}


async def test_a_text_returning_tool_becomes_output() -> None:
    session = _FakeSession(_TextResult("some text"))

    result = await _tools(session).call(NMAP_SCAN_TOOL, {"target": "10.0.0.5"})

    assert result["ok"] is True
    assert result["output"] == "some text"


async def test_a_tool_error_is_data_not_an_exception() -> None:
    session = _FakeSession(_TextResult("it went wrong", is_error=True))

    result = await _tools(session).call(NMAP_SCAN_TOOL, {"target": "10.0.0.5"})

    assert result["ok"] is False
    assert "it went wrong" in result["error"]


async def test_a_transport_failure_mid_call_is_data_not_an_exception() -> None:
    session = _FakeSession(raises=RuntimeError("connection reset"))

    result = await _tools(session).call(NMAP_SCAN_TOOL, {"target": "10.0.0.5"})

    assert result["ok"] is False
    assert "connection reset" in result["error"]


def test_text_extraction_ignores_non_text_blocks() -> None:
    class _Image:
        type = "image"

    class _Mixed:
        def __init__(self) -> None:
            self.content: list[object] = [_TextBlock("kept"), _Image()]

    assert _text_of(_Mixed()) == "kept"
    assert _text_of(object()) == ""


# ---------------------------------------------------------- diagnostics --


def test_the_root_cause_of_a_nested_task_group_failure_is_surfaced() -> None:
    """Every transport failure otherwise reads "unhandled errors in a TaskGroup"."""
    inner = ConnectionRefusedError("nothing listening")
    nested = BaseExceptionGroup("outer", [BaseExceptionGroup("inner", [inner])])

    described = _root_cause(nested)

    assert "ConnectionRefusedError" in described
    assert "nothing listening" in described


def test_the_root_cause_of_a_plain_exception_is_itself() -> None:
    assert "ValueError: bad" == _root_cause(ValueError("bad"))


# ------------------------------------------------------------ degradation --


async def test_an_unreachable_server_yields_no_session_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        # Port 1 is reserved and never listening.
        mcp_server_url="http://127.0.0.1:1/mcp",
        mcp_timeout_seconds=2.0,
        internal_key="test-key",
    )
    monkeypatch.delenv("MCP_SERVER_URL", raising=False)

    async with open_tools(settings) as tools:
        assert tools is None


async def test_the_agent_still_produces_findings_with_no_mcp_at_all() -> None:
    """The reason the deterministic engine exists.

    The autouse ``_no_mcp`` fixture forces the unavailable path, so everything
    this run reports came from the bundled knowledge base.
    """
    state = initial_vulnerability_state(source="nmap", raw_input=SCANNABLE, asset="10.0.0.5")

    result = await vulnerability_graph.GRAPH.ainvoke(state)

    assert len(result["findings"]) >= 2
    assert not result["enrichment"]["available"]
    for finding in result["findings"]:
        assert finding.evidence["assessment"]["assessed_by"] == "rules-only"


async def test_no_target_and_no_scanner_is_reported_as_such() -> None:
    """Not as a clean scan: nothing was assessed."""
    state = initial_vulnerability_state(source="nmap", asset="10.0.0.5")

    result = await vulnerability_graph.GRAPH.ainvoke(state)

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert "No vulnerability scan was performed" in finding.title
    assert result["scan_info"]["status"] == "scanner-unavailable"


# ------------------------------------------------------------------ auth --


def test_the_internal_key_is_sent_as_a_header_name_both_sides_agree_on() -> None:
    """The MCP server mirrors this constant locally; they must not drift."""
    assert INTERNAL_KEY_HEADER == "X-Internal-Key"
