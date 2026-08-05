"""Graph state for the web application security agent."""

from __future__ import annotations

from typing import Any, NotRequired

from ai_engine.agents.common.state import AgentState


class WebappState(AgentState):
    """Web-application-specific working state.

    Phase 2: ``parsed_alerts`` holds the structured output from ZAP or Nuclei.
    ``owasp_categories`` maps OWASP Top 10 categories to the alerts that fall under them.
    """

    target_url: str | None
    parsed_alerts: list[dict[str, Any]]
    owasp_categories: dict[str, list[dict[str, Any]]]
    raw_findings: NotRequired[list[dict[str, Any]]]
