"""Node functions for the phishing detection agent. All stubs in Phase 1."""

from __future__ import annotations

from typing import Any

from cyberagents_contracts import AgentKind
from langchain_core.messages import HumanMessage, SystemMessage

from ai_engine.agents.common.placeholder import placeholder_finding
from ai_engine.agents.common.untrusted import wrap_untrusted
from ai_engine.agents.phishing.prompts import SYSTEM_PROMPT
from ai_engine.agents.phishing.state import PhishingState
from ai_engine.core.logging import get_logger

logger = get_logger(__name__)


async def normalize(state: PhishingState) -> dict[str, Any]:
    """Extract headers, URLs, and domains.

    TODO(phase-2): real MIME parsing, URL extraction, and SPF/DKIM/DMARC lookup.
    """
    raw = state["raw_input"]
    logger.info("phishing.normalize", source=state["source"], length=len(raw))

    return {
        "normalized": {"source": state["source"], "byte_length": len(raw), "parsed": False},
        "headers": {},
        "urls": [],
        "domains": [],
        "auth_results": {},
    }


async def reason(state: PhishingState) -> dict[str, Any]:
    """Assemble the prompt. Does not call the model in Phase 1."""
    fenced = wrap_untrusted("email or URL artifact", state["raw_input"])

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=fenced)]
    logger.info("phishing.reason", messages=len(messages), llm_invoked=False)
    return {"messages": messages}


async def emit_findings(state: PhishingState) -> dict[str, Any]:
    """Produce contract-shaped findings."""
    finding = placeholder_finding(
        agent=AgentKind.phishing,
        source=state["source"],
        asset=state["asset"],
        raw_input=state["raw_input"],
        summary="The artifact was received but not evaluated for phishing indicators.",
    )

    logger.info("phishing.emit_findings", count=1)
    return {"findings": [finding]}
