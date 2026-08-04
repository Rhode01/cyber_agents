"""Base graph state shared by all four agents.

``raw_input`` is untrusted by definition - it is whatever a security tool
emitted. It is carried through the graph as data and only ever reaches a prompt
through ``wrap_untrusted``.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from cyberagents_contracts import FindingCreate
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """State every agent graph carries."""

    # ---- inputs, set once by the router -------------------------------------
    source: str
    asset: str | None
    raw_input: str
    context: dict[str, Any]

    # ---- working state, written by nodes ------------------------------------
    normalized: dict[str, Any]
    messages: Annotated[list[AnyMessage], add_messages]

    # ---- output ------------------------------------------------------------
    findings: list[FindingCreate]


def initial_state(
    *,
    source: str,
    raw_input: str,
    asset: str | None = None,
    context: dict[str, Any] | None = None,
) -> AgentState:
    """Build a fully populated starting state."""
    return AgentState(
        source=source,
        asset=asset,
        raw_input=raw_input,
        context=context or {},
        normalized={},
        messages=[],
        findings=[],
    )
