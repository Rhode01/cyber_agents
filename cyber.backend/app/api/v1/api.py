"""Aggregate router mounted by the FastAPI application."""

from __future__ import annotations

from fastapi import APIRouter

from app.api import agents, discovery, email_connect, findings, health, runs, scans, settings, system

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(agents.router)
api_router.include_router(discovery.router)
api_router.include_router(settings.router)
api_router.include_router(runs.router)
api_router.include_router(system.router)
api_router.include_router(email_connect.router)

__all__ = ["api_router"]
