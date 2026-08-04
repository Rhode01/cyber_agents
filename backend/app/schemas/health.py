"""Health check DTOs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Liveness of the backend process itself."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    service: str = "backend"
    version: str
    app_env: str


class DbHealthResponse(BaseModel):
    """Result of a real round trip to PostgreSQL over the async driver."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "error"]
    service: str = "backend"
    database: Literal["postgresql"] = "postgresql"
    driver: Literal["asyncpg"] = "asyncpg"
    latency_ms: float | None = Field(default=None, ge=0)
    server_version: str | None = None
    error: str | None = None
