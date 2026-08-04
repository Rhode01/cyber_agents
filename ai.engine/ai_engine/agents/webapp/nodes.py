"""Node functions for the web application security agent. All stubs in Phase 1."""

from __future__ import annotations

from typing import Any

from cyberagents_contracts import AgentKind
from langchain_core.messages import HumanMessage, SystemMessage

from ai_engine.agents.common.placeholder import placeholder_finding
from ai_engine.agents.common.untrusted import wrap_untrusted
from ai_engine.agents.webapp.prompts import SYSTEM_PROMPT
from ai_engine.agents.webapp.state import WebappState
from ai_engine.core.logging import get_logger

logger = get_logger(__name__)


async def normalize(state: WebappState) -> dict[str, Any]:
    """Parse a scanner report into endpoints and alerts.

    TODO(phase-2): dispatch on ``source`` to a ZAP or Nuclei report parser.
    """
    raw = state["raw_input"]
    logger.info("webapp.normalize", source=state["source"], length=len(raw))

    return {
        "normalized": {"source": state["source"], "byte_length": len(raw), "parsed": False},
        "target_url": state["asset"],
        "endpoints": [],
        "alerts": [],
        "owasp_categories": [],
    }


async def reason(state: WebappState) -> dict[str, Any]:
    """Assemble the prompt. Does not call the model in Phase 1."""
    fenced = wrap_untrusted("web scanner report", state["raw_input"])

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=fenced)]
    logger.info("webapp.reason", messages=len(messages), llm_invoked=False)
    return {"messages": messages}


async def emit_findings(state: WebappState) -> dict[str, Any]:
    """Produce contract-shaped findings."""
    finding = placeholder_finding(
        agent=AgentKind.webapp,
        source=state["source"],
        asset=state["asset"],
        raw_input=state["raw_input"],
        summary="The scanner report was received but not classified against the OWASP Top 10.",
    )

    logger.info("webapp.emit_findings", count=1)
    return {"findings": [finding]}
