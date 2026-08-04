"""Phishing detection agent.

Emails, URLs, and domains in; SPF/DKIM/DMARC alignment, reputation, and a
verdict out.
"""

from ai_engine.agents.phishing.graph import GRAPH, build_graph
from ai_engine.agents.phishing.state import PhishingState

__all__ = ["GRAPH", "PhishingState", "build_graph"]
