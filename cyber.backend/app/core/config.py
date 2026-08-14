"""Backend configuration. Every value comes from the environment."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Backend settings, loaded from the environment or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------- general --
    app_name: str = "Cybersecurity Agents Platform backend"
    app_env: Literal["local", "ci", "staging", "production"] = "local"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ------------------------------------------------------------- database --
    # The backend is the only module that holds a database URL.
    database_url: str = "postgresql+asyncpg://cyberagents:cyberagents@localhost:5432/cyberagents"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_pre_ping: bool = True

    # ---------------------------------------------------------------- redis --
    redis_url: str = "redis://localhost:6379/0"

    # ------------------------------------------------------------ ai.engine --
    ai_engine_url: str = "http://localhost:8003"
    # Agents can launch live scans (nmap, nuclei) against a target, so a run
    # legitimately takes minutes rather than seconds. This is the outermost link
    # of the scan timeout chain and must exceed the ai.engine's
    # MCP_TIMEOUT_SECONDS, which must in turn exceed the MCP server's
    # SCAN_TIMEOUT_SECONDS. One assessment is a scan plus CVE enrichment plus a
    # model call, so the headroom over the scan alone is deliberate.
    ai_engine_timeout_seconds: float = Field(default=420.0, gt=0)

    # ------------------------------------------------------------- mcpserver --
    mcp_server_url: str = "http://mcpserver:8004"

    # ----------------------------------------------------------------- http --
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # ------------------------------------------------------------- security --
    # Placeholder only. Real authentication and RBAC are deferred past Phase 1.
    secret_key: str = "change-me-in-every-real-deployment"  # noqa: S105 - obvious placeholder

    # Shared secret for service-to-service calls. Sent outbound to the ai.engine,
    # and required inbound on the finding-write routes the ai.engine calls back on.
    # This authenticates a *service*, never a user: browser-facing routes are still
    # unauthenticated, which is what ``secret_key`` above is reserved for.
    internal_key: str = ""

    @field_validator("database_url")
    @classmethod
    def _require_async_driver(cls, value: str) -> str:
        """Fail fast if someone points the async engine at a sync driver."""
        if not value.startswith("postgresql+asyncpg://"):
            msg = "database_url must use the postgresql+asyncpg:// driver"
            raise ValueError(msg)
        return value

    @field_validator("ai_engine_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def enforce_internal_key(self) -> bool:
        """Should the service-to-service write routes require the key?

        False only when no key is configured, which is the local-development
        default. Unlike the ai.engine and MCP server, the backend does not refuse
        to start without one: it also serves the browser, and a backend that will
        not boot takes the whole UI with it. The routes that matter are the ones
        guarded below, and they are not routes a browser calls.
        """
        return bool(self.internal_key)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
