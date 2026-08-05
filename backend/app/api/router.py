"""Aggregate router mounted by the FastAPI application."""

from __future__ import annotations

from fastapi import APIRouter

from app.api import agents, findings, health, scans

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(agents.router)

__all__ = ["api_router"]
