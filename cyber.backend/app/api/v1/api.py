"""Aggregate v1 router mounted by the FastAPI application.

One include per endpoint module. The settings and email-connect endpoints were
removed during the restructure: they stored OAuth client secrets, IMAP passwords
and Gmail refresh tokens as plaintext rows and served them back over an
unauthenticated GET. Credentials now come from the environment only.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.agents import router as agents_router
from app.api.v1.endpoints.discovery import router as discovery_router
from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.messages import router as messages_router
from app.api.v1.endpoints.runs import router as runs_router
from app.api.v1.endpoints.scans import router as scans_router
from app.api.v1.endpoints.system import router as system_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(scans_router)
api_router.include_router(messages_router)
api_router.include_router(findings_router)
api_router.include_router(agents_router)
api_router.include_router(runs_router)
api_router.include_router(discovery_router)
api_router.include_router(system_router)

__all__ = ["api_router"]
