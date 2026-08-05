"""The phishing detection StateGraph.

MVP shape:

    START -> scan -> normalize -> rule_check -> reason -> emit_findings -> END
                                        \\____________/^
                          (short-circuit if rules flag obvious phishing)

The ``scan`` node runs live DNS + HTTP checks against the analyst's
URL/domain/email when no email artifact is supplied.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from ai_engine.agents.phishing.nodes import emit_findings, normalize, reason, rule_check, scan
from ai_engine.agents.phishing.state import PhishingState


def should_reason(state: PhishingState) -> str:
    """Decide whether to call the LLM or skip straight to emitting findings.

    If 3 or more deterministic rules fire, it's obviously phishing and we can
    save the LLM tokens and latency.
    """
    if len(state.get("rule_hits", [])) >= 3:
        return "emit_findings"
    return "reason"


def build_graph() -> Any:
    """Build and compile the phishing detection graph."""
    builder = StateGraph(PhishingState)

    builder.add_node("scan", scan)
    builder.add_node("normalize", normalize)
    builder.add_node("rule_check", rule_check)
    builder.add_node("reason", reason)
    builder.add_node("emit_findings", emit_findings)

    builder.add_edge(START, "scan")
    builder.add_edge("scan", "normalize")
    builder.add_edge("normalize", "rule_check")

    builder.add_conditional_edges(
        "rule_check",
        should_reason,
        {"reason": "reason", "emit_findings": "emit_findings"},
    )

    builder.add_edge("reason", "emit_findings")
    builder.add_edge("emit_findings", END)

    return builder.compile()


GRAPH = build_graph()
