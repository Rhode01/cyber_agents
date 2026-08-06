"""One FastAPI router per agent, plus health and network discovery.

Each agent router owns exactly one LangGraph graph and exposes it at
``POST /agents/<name>/analyze``. Nothing else routes to a graph. Discovery is
not an agent - it feeds the pipeline a target list - so it lives on its own
router at ``POST /discovery/run``.
"""

from ai_engine.routers import discovery, health, network, phishing, vulnerability, webapp

AGENT_ROUTERS = (vulnerability, phishing, network, webapp)

__all__ = [
    "AGENT_ROUTERS",
    "discovery",
    "health",
    "network",
    "phishing",
    "vulnerability",
    "webapp",
]
