"""The web application security StateGraph.

MVP shape:

    START -> scan -> normalize -> categorize -> reason -> emit_findings -> END

The ``scan`` node launches a Nuclei scan against the analyst's target URL when
no scanner report is supplied.
"""

from __future__ import annotations

from typing import Any

from ai_engine.agents.common.graph import build_linear_graph
from ai_engine.agents.webapp.nodes import categorize, emit_findings, normalize, reason, scan
from ai_engine.agents.webapp.state import WebappState


def build_graph() -> Any:
    """Build and compile the web application security graph."""
    return build_linear_graph(
        WebappState,
        [
            ("scan", scan),
            ("normalize", normalize),
            ("categorize", categorize),
            ("reason", reason),
            ("emit_findings", emit_findings),
        ],
    )


GRAPH = build_graph()
