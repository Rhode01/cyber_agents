"""Graph state for the web application security agent."""

from __future__ import annotations

from typing import Any, NotRequired

from ai_engine.agents.common.state import AgentState


class WebappState(AgentState):
    """Web-application-specific working state.

    These keys are NotRequired because the router seeds only the base state and
    ``normalize`` is what fills them in.

    TODO(phase-2): populated by real ZAP and Nuclei report parsing and OWASP
    Top 10 classification.
    """

    target_url: NotRequired[str | None]
    endpoints: NotRequired[list[dict[str, Any]]]
    alerts: NotRequired[list[dict[str, Any]]]
    owasp_categories: NotRequired[list[str]]
