"""Graph state for the network traffic analysis agent."""

from __future__ import annotations

from typing import Any, NotRequired

from ai_engine.agents.common.state import AgentState


class NetworkState(AgentState):
    """Network-specific working state.

    These keys are NotRequired because the router seeds only the base state and
    ``normalize`` is what fills them in.

    TODO(phase-2): populated by real NetFlow / Zeek / Suricata parsing and
    baseline comparison.
    """

    flows: NotRequired[list[dict[str, Any]]]
    top_talkers: NotRequired[list[dict[str, Any]]]
    alerts: NotRequired[list[dict[str, Any]]]
    baseline_deviation: NotRequired[dict[str, Any]]
