"""The phishing detection StateGraph.

    START → normalize → detect → enrich → score → reason → emit_findings → END

Linear, with no conditional edges at all. That is a deliberate difference from the
previous version, which had two:

* ``route_after_scan`` skipped everything for local targets - unnecessary now, because
  the backend rejects local URLs at intake and there is no self-launched scanning left.
* ``should_reason`` sent the graph straight to ``emit_findings`` when three or more rules
  fired, on the theory that obvious phishing needs no explanation. It is exactly
  backwards: the messages that most need an analyst-facing write-up are the ones with the
  most evidence, and the shortcut meant they were the only ones that never got one.

A conditional edge also hands control flow to a decision that attacker-supplied content
can influence. A straight line cannot be steered.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.phishing.nodes import (
    detect,
    emit_findings,
    enrich,
    normalize,
    reason,
    score,
)
from app.agents.phishing.state import PhishingState


def build_graph() -> Any:
    """Build and compile the phishing detection graph."""
    builder = StateGraph(PhishingState)

    builder.add_node("normalize", normalize)
    builder.add_node("detect", detect)
    builder.add_node("enrich", enrich)
    builder.add_node("score", score)
    builder.add_node("reason", reason)
    builder.add_node("emit_findings", emit_findings)

    builder.add_edge(START, "normalize")
    builder.add_edge("normalize", "detect")
    # enrich runs before score, so any indicator it adds is included in the floor.
    builder.add_edge("detect", "enrich")
    builder.add_edge("enrich", "score")
    builder.add_edge("score", "reason")
    builder.add_edge("reason", "emit_findings")
    builder.add_edge("emit_findings", END)

    return builder.compile()


GRAPH = build_graph()
