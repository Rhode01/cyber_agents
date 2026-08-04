"""Graph state for the phishing detection agent."""

from __future__ import annotations

from typing import Any, NotRequired

from ai_engine.agents.common.state import AgentState


class PhishingState(AgentState):
    """Phishing-specific working state.

    These keys are NotRequired because the router seeds only the base state and
    ``normalize`` is what fills them in.

    TODO(phase-2): populated by real MIME parsing, URL extraction, and
    SPF/DKIM/DMARC evaluation.
    """

    headers: NotRequired[dict[str, str]]
    urls: NotRequired[list[str]]
    domains: NotRequired[list[str]]
    auth_results: NotRequired[dict[str, Any]]
