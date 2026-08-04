"""mcpserver configuration.

This module holds no database settings. Anything it eventually needs from
platform state it will fetch from the backend over HTTP.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """mcpserver settings, loaded from the environment or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    mcp_server_name: str = "cyber-agents"
    # Containers must bind all interfaces; S104 is disabled for this module.
    mcp_host: str = "0.0.0.0"
    mcp_port: int = Field(default=8004, ge=1, le=65535)

    backend_url: str = "http://localhost:8000"
    backend_timeout_seconds: float = Field(default=30.0, gt=0)

    # The MCP SDK rejects unexpected Host and Origin headers as DNS-rebinding
    # protection, answering 421. Leave these empty to accept the local defaults
    # below; set them explicitly for any real deployment hostname.
    mcp_allowed_hosts: list[str] = Field(default_factory=list)
    mcp_allowed_origins: list[str] = Field(default_factory=list)

    @field_validator("backend_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @property
    def resolved_allowed_hosts(self) -> list[str]:
        """Hosts the MCP transport will answer for."""
        if self.mcp_allowed_hosts:
            return self.mcp_allowed_hosts

        # "mcpserver" is the compose service name, so other containers reach it.
        names = ["localhost", "127.0.0.1", "mcpserver"]
        return [*names, *(f"{name}:{self.mcp_port}" for name in names)]

    @property
    def resolved_allowed_origins(self) -> list[str]:
        """Browser origins the MCP transport will answer for."""
        if self.mcp_allowed_origins:
            return self.mcp_allowed_origins
        return [f"http://localhost:{self.mcp_port}", f"http://127.0.0.1:{self.mcp_port}"]


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
