"""ai.engine configuration.

The LLM is reconfigurable entirely through the environment: model name, an
optional OpenAI-compatible base URL, and the API key. Nothing about the provider
is hard-coded in the agent code, so swapping models never means a code change.

There is deliberately no database setting here. The ai.engine reaches platform
state only through ``backend_url``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ai.engine settings, loaded from the environment or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------- general --
    app_name: str = "Cybersecurity Agents Platform ai.engine"
    app_env: Literal["local", "ci", "staging", "production"] = "local"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ------------------------------------------------------------------ llm --
    # Default provider is OpenAI's hosted API. Leave openai_base_url unset to
    # use it; point it elsewhere for any OpenAI-compatible endpoint.
    openai_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"
    openai_base_url: str = ""
    openai_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    openai_timeout_seconds: float = Field(default=60.0, gt=0)
    openai_max_retries: int = Field(default=2, ge=0, le=10)

    # -------------------------------------------------------------- backend --
    backend_url: str = "http://localhost:8000"
    backend_timeout_seconds: float = Field(default=30.0, gt=0)

    @field_validator("backend_url", "openai_base_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @property
    def resolved_base_url(self) -> str | None:
        """None means "use the provider default", which is OpenAI's hosted API."""
        return self.openai_base_url or None

    @property
    def llm_is_configured(self) -> bool:
        """Whether a live call could succeed. Phase 1 never makes one."""
        return bool(self.openai_api_key)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
