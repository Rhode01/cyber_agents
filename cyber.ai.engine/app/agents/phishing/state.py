"""Graph state for the phishing detection agent."""

from __future__ import annotations

from typing import Any, NotRequired

from app.agents.common.state import AgentState


class PhishingState(AgentState):
    """Phishing-specific working state.

    Phase 2: ``parsed_email`` holds the structured MIME output.
    ``rule_hits`` are deterministic flags from the rule_check node.
    ``verdict`` and ``explanation`` are from the LLM or rules.
    """

    parsed_email: dict[str, Any]
    rule_hits: list[str]
    verdict: str | None
    explanation: str | None
    raw_findings: NotRequired[list[dict[str, Any]]]
    local_target: NotRequired[bool]
