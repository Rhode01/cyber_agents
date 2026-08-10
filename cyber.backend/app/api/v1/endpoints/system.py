"""System module status.

One endpoint that reports the health of every platform module so the dashboard
can render a live module map instead of a hardcoded list of addresses.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from sqlalchemy import text

from app.api.deps import SessionDep, SettingsDep

router = APIRouter(prefix="/system", tags=["system"])

_MODULE_TIMEOUT_SECONDS = 3.0


def _host_of(url: str) -> str:
    """The host:port a URL points at, for display.

    Derived rather than hardcoded: the previous version reported `localhost:8003`
    whatever the configured URL was, so under compose the module map confidently
    showed addresses that were not the ones being checked.

    Uses ``hostname``/``port`` rather than ``netloc`` on purpose - ``netloc``
    keeps any ``user:pass@`` prefix, which would put the database password in an
    unauthenticated response.
    """
    parts = urlsplit(url)
    if not parts.hostname:
        return "(unknown)"
    return f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname


class ModuleStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    host: str
    status: str = Field(description="ok | down | unknown")
    detail: str = ""


class SystemModules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ModuleStatus] = Field(default_factory=list)


async def _check_http(name: str, host: str, url: str) -> ModuleStatus:
    try:
        async with httpx.AsyncClient(timeout=_MODULE_TIMEOUT_SECONDS) as client:
            response = await client.get(url)
        if response.status_code == 200:
            return ModuleStatus(name=name, host=host, status="ok")
        detail = f"HTTP {response.status_code}"
        return ModuleStatus(name=name, host=host, status="down", detail=detail)
    except httpx.HTTPError as err:
        return ModuleStatus(name=name, host=host, status="down", detail=type(err).__name__)


async def _check_redis(url: str) -> ModuleStatus:
    host = _host_of(url)
    try:
        client = Redis.from_url(
            url,
            socket_timeout=_MODULE_TIMEOUT_SECONDS,
            socket_connect_timeout=_MODULE_TIMEOUT_SECONDS,
        )
        pong = await client.ping()
        await client.aclose()
        if pong:
            return ModuleStatus(name="redis", host=host, status="ok")
        return ModuleStatus(name="redis", host=host, status="down", detail="ping failed")
    except Exception as err:
        return ModuleStatus(name="redis", host=host, status="down", detail=type(err).__name__)


@router.get("/modules", response_model=SystemModules, summary="Health of every platform module")
async def system_modules(session: SessionDep, settings: SettingsDep) -> SystemModules:
    """Ping the database, redis, ai.engine, and the MCP server concurrently."""
    db_host = _host_of(settings.database_url)

    async def _check_db() -> ModuleStatus:
        try:
            await session.execute(text("SELECT 1"))
            return ModuleStatus(name="postgres", host=db_host, status="ok")
        except Exception as err:
            return ModuleStatus(
                name="postgres", host=db_host, status="down", detail=type(err).__name__
            )

    results = await asyncio.gather(
        _check_db(),
        _check_redis(settings.redis_url),
        _check_http(
            "ai.engine", _host_of(settings.ai_engine_url), f"{settings.ai_engine_url}/health"
        ),
        _check_http(
            "mcpserver", _host_of(settings.mcp_server_url), f"{settings.mcp_server_url}/health"
        ),
    )
    return SystemModules(items=list(results))
