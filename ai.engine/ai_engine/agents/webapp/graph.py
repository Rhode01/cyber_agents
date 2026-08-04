"""The web application security StateGraph.

Built through ``agents.common.graph``; see ``agents.vulnerability.graph`` for the
same shape wired explicitly.

    START -> normalize -> reason -> emit_findings -> END
"""

from __future__ import annotations

from typing import Any

from ai_engine.agents.common.graph import build_linear_graph
from ai_engine.agents.webapp.nodes import emit_findings, normalize, reason
from ai_engine.agents.webapp.state import WebappState


def build_graph() -> Any:
    """Build and compile the web application security graph."""
    return build_linear_graph(
        WebappState,
        [("normalize", normalize), ("reason", reason), ("emit_findings", emit_findings)],
    )


GRAPH = build_graph()
