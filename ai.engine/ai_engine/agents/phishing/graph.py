"""The phishing detection StateGraph.

Built through ``agents.common.graph`` because its Phase 1 shape is identical to
the reference implementation in ``agents.vulnerability.graph``:

    START -> normalize -> reason -> emit_findings -> END

TODO(phase-2): wire this graph explicitly once it needs its own branches and a
tool node for ``tools.TOOLS``.
"""

from __future__ import annotations

from typing import Any

from ai_engine.agents.common.graph import build_linear_graph
from ai_engine.agents.phishing.nodes import emit_findings, normalize, reason
from ai_engine.agents.phishing.state import PhishingState


def build_graph() -> Any:
    """Build and compile the phishing detection graph."""
    return build_linear_graph(
        PhishingState,
        [("normalize", normalize), ("reason", reason), ("emit_findings", emit_findings)],
    )


GRAPH = build_graph()
