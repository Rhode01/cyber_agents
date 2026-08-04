"""Node functions for the network traffic analysis agent. All stubs in Phase 1."""

from __future__ import annotations

from typing import Any

from cyberagents_contracts import AgentKind
from langchain_core.messages import HumanMessage, SystemMessage

from ai_engine.agents.common.placeholder import placeholder_finding
from ai_engine.agents.common.untrusted import wrap_untrusted
from ai_engine.agents.network.prompts import SYSTEM_PROMPT
from ai_engine.agents.network.state import NetworkState
from ai_engine.core.logging import get_logger

logger = get_logger(__name__)


async def normalize(state: NetworkState) -> dict[str, Any]:
    """Parse flow records and alerts into a common shape.

    TODO(phase-2): dispatch on ``source`` to a NetFlow / Zeek / Suricata parser.
    """
    raw = state["raw_input"]
    logger.info("network.normalize", source=state["source"], length=len(raw))

    return {
        "normalized": {"source": state["source"], "byte_length": len(raw), "parsed": False},
        "flows": [],
        "top_talkers": [],
        "alerts": [],
        "baseline_deviation": {},
    }


async def reason(state: NetworkState) -> dict[str, Any]:
    """Assemble the prompt. Does not call the model in Phase 1."""
    fenced = wrap_untrusted("network telemetry", state["raw_input"])

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=fenced)]
    logger.info("network.reason", messages=len(messages), llm_invoked=False)
    return {"messages": messages}


async def emit_findings(state: NetworkState) -> dict[str, Any]:
    """Produce contract-shaped findings."""
    finding = placeholder_finding(
        agent=AgentKind.network,
        source=state["source"],
        asset=state["asset"],
        raw_input=state["raw_input"],
        summary="Telemetry was received but no baseline or anomaly analysis ran.",
    )

    logger.info("network.emit_findings", count=1)
    return {"findings": [finding]}
