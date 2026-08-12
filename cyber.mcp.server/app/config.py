"""app configuration.

This module holds no database settings. Anything it eventually needs from
platform state it will fetch from the backend over HTTP.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """app settings, loaded from the environment or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["local", "ci", "staging", "production"] = "local"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    mcp_server_name: str = "cyber-agents"
    # Containers must bind all interfaces; S104 is disabled for this module.
    mcp_host: str = "0.0.0.0"
    mcp_port: int = Field(default=8004, ge=1, le=65535)

    backend_url: str = "http://localhost:8000"
    backend_timeout_seconds: float = Field(default=30.0, gt=0)

    # Shared secret for service-to-service calls, in both directions: required on
    # inbound /mcp requests and sent on outbound backend requests.
    internal_key: str = ""

    # The MCP SDK rejects unexpected Host and Origin headers as DNS-rebinding
    # protection, answering 421. Leave these empty to accept the local defaults
    # below; set them explicitly for any real deployment hostname.
    mcp_allowed_hosts: list[str] = Field(default_factory=list)
    mcp_allowed_origins: list[str] = Field(default_factory=list)

    # Scanning limits. The scan tools refuse anything outside these networks -
    # an MCP tool that runs nmap against an arbitrary string is a scanning proxy
    # for whoever can reach the port, so the default is the private space only.
    scan_allowed_targets: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
        ]
    )
    scan_timeout_seconds: float = Field(default=120.0, gt=0)
    scan_nmap_path: str = Field(
        default="nmap",
        description=(
            "The nmap executable. A bare name is resolved through PATH, which is the "
            "right default inside the container image. Set an absolute path where nmap "
            "is installed but not on PATH - notably the Windows installer, which puts it "
            "in 'C:\\Program Files (x86)\\Nmap' and adds nothing to the machine PATH. "
            "Without this the tool reports 'nmap is not installed' while the binary is "
            "plainly there, and the service has to be relaunched with a doctored "
            "environment to work at all."
        ),
    )
    cve_lookup_url: str = "https://cve.circl.lu/api/cve"
    cve_lookup_timeout_seconds: float = Field(default=8.0, gt=0)
    cve_cache_ttl_seconds: float = Field(default=3600.0, ge=0)

    # Phishing link inspection. `fetch_url` is the only tool that contacts a host an
    # attacker chose, so it needs two switches to agree: this one, and the per-request
    # opt-in the analyst sets. That means an operator can disable all egress regardless of
    # what any request asks for, which a per-request flag alone could not provide.
    #
    # Default off. Fetching tells whoever runs the phishing site that the message is being
    # investigated, and that should be a decision rather than a side effect.
    phishing_fetch_enabled: bool = Field(
        default=False,
        description=(
            "Allow fetch_url to retrieve linked pages. Both this and the per-request "
            "opt-in must be true before any request leaves the host."
        ),
    )

    @field_validator("backend_url", "cve_lookup_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @model_validator(mode="after")
    def _require_internal_key_outside_local(self) -> Settings:
        """Fail closed: only local development may run without a key.

        Refusing at startup rather than per-request means a misconfigured deploy
        is a container that will not come up, not one that quietly serves an
        unauthenticated scan endpoint.
        """
        if self.app_env != "local" and not self.internal_key:
            msg = (
                f"INTERNAL_KEY must be set when APP_ENV is {self.app_env!r}. "
                "The MCP endpoint exposes scan and agent-run tools; it is not safe "
                "to serve them unauthenticated."
            )
            raise ValueError(msg)
        return self

    @property
    def enforce_internal_key(self) -> bool:
        """Should inbound requests be rejected without a valid key?

        False only in local development with no key configured. Setting a key
        locally turns enforcement on, so the production path can be exercised.
        """
        return bool(self.internal_key)

    @property
    def resolved_allowed_hosts(self) -> list[str]:
        """Hosts the MCP transport will answer for."""
        if self.mcp_allowed_hosts:
            return self.mcp_allowed_hosts

        # "mcpserver" is the compose service name, so other containers reach it
        # under that Host header. "app" is kept for anyone who renamed it back.
        names = ["localhost", "127.0.0.1", "mcpserver", "app"]
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
