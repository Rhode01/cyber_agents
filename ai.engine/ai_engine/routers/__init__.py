"""One FastAPI router per agent, plus health.

Each agent router owns exactly one LangGraph graph and exposes it at
``POST /agents/<name>/analyze``. Nothing else routes to a graph.
"""

from ai_engine.routers import health, network, phishing, vulnerability, webapp

AGENT_ROUTERS = (vulnerability, phishing, network, webapp)

__all__ = ["AGENT_ROUTERS", "health", "network", "phishing", "vulnerability", "webapp"]
