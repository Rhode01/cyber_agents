"""The network traffic analysis StateGraph.

MVP shape:

    START -> scan -> normalize -> detect -> reason -> emit_findings -> END

The ``scan`` node takes a live ``ss`` TCP snapshot against the analyst's target
when no telemetry artifact is supplied.
"""

from __future__ import annotations

from typing import Any

from ai_engine.agents.common.graph import build_linear_graph
from ai_engine.agents.network.nodes import detect, emit_findings, normalize, reason, scan
from ai_engine.agents.network.state import NetworkState


def build_graph() -> Any:
    """Build and compile the network traffic analysis graph."""
    return build_linear_graph(
        NetworkState,
        [
            ("scan", scan),
            ("normalize", normalize),
            ("detect", detect),
            ("reason", reason),
            ("emit_findings", emit_findings),
        ],
    )


GRAPH = build_graph()
