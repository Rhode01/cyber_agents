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

from pydantic import Field, field_validator, model_validator
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

    # ------------------------------------------------------------------ mcp --
    # Agent tools (nmap, CVE enrichment, exposure) are executed by the MCP
    # server, not here. Unreachable is survivable: the deterministic rule engine
    # still produces findings, just without enrichment.
    mcp_server_url: str = "http://localhost:8004/mcp"
    mcp_timeout_seconds: float = Field(default=180.0, gt=0)

    # ------------------------------------------------------------- phishing --
    phishing_max_indicators: int = Field(
        default=30,
        ge=1,
        le=200,
        description=(
            "How many indicators reach the model. Chosen for headroom under "
            "wrap_untrusted's character limit rather than measured against a real "
            "corpus. Anything beyond the cap is the weakest evidence, is excluded from "
            "the prompt, and is listed in the finding's evidence so a capped analysis "
            "never reads as a complete one."
        ),
    )
    phishing_enrichment_enabled: bool = Field(
        default=True,
        description=(
            "Master switch for live lookups. Off means the agent works entirely from its "
            "bundled knowledge, which costs detail and no correctness - enrichment may "
            "only ever add signal."
        ),
    )

    # -------------------------------------------------------------- security --
    # Shared secret for service-to-service calls. Sent on outbound requests to
    # the backend and the MCP server, and required on inbound agent requests.
    internal_key: str = ""

    @field_validator("backend_url", "openai_base_url", "mcp_server_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @model_validator(mode="after")
    def _require_internal_key_outside_local(self) -> Settings:
        """Fail closed: only local development may run without a key.

        The agent routes launch scans and spend model budget. Refusing at startup
        makes a misconfigured deploy a container that does not come up, rather
        than one that quietly serves those routes to anyone.
        """
        if self.app_env != "local" and not self.internal_key:
            msg = (
                f"INTERNAL_KEY must be set when APP_ENV is {self.app_env!r}. "
                "The agent routes trigger scans and model calls; they are not safe "
                "to serve unauthenticated."
            )
            raise ValueError(msg)
        return self

    @property
    def enforce_internal_key(self) -> bool:
        """Should inbound agent requests be rejected without a valid key?

        False only in local development with no key configured. Setting a key
        locally turns enforcement on, so the production path can be exercised.
        """
        return bool(self.internal_key)

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
