"""Aggregate v1 router for the ai.engine.

One router per agent, plus health and network discovery. Each agent router owns
exactly one LangGraph graph and exposes it at ``POST /agents/<name>/analyze``;
nothing else routes to a graph. Discovery is not an agent - it feeds the pipeline
a target list - so it keeps its own router at ``POST /discovery/run``.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.discovery import router as discovery_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.network import router as network_router
from app.api.v1.endpoints.phishing import router as phishing_router
from app.api.v1.endpoints.vulnerability import router as vulnerability_router
from app.api.v1.endpoints.webapp import router as webapp_router

# The agents the platform exposes, in the order the pipeline runs them. Health
# reports this list, so adding an agent here is the single place to register it.
MOUNTED_AGENTS = ("vulnerability", "phishing", "network", "webapp")

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(vulnerability_router)
api_router.include_router(phishing_router)
api_router.include_router(network_router)
api_router.include_router(webapp_router)
api_router.include_router(discovery_router)

__all__ = ["MOUNTED_AGENTS", "api_router"]
