"""Graph state for the network traffic analysis agent."""

from __future__ import annotations

from typing import Any, NotRequired

from ai_engine.agents.common.state import AgentState


class NetworkState(AgentState):
    """Network-specific working state.

    Phase 2: ``metrics`` contains parsed flow statistics.
    ``anomalies`` contains rule-based detections (DNS flood, port scan).
    """

    metrics: dict[str, Any]
    anomalies: list[dict[str, Any]]
    traffic_window_seconds: int
    raw_findings: NotRequired[list[dict[str, Any]]]
    parsed_data: NotRequired[list[Any]]  # temporary key passed to detect
