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
    scan_resolve_hostnames: bool = Field(
        default=True,
        description=(
            "Resolve a hostname target and apply the allowlist to every address it "
            "returns. This cannot widen scope - the allowlist is still the only gate - "
            "it just means a client can name their server instead of looking its "
            "address up first. Set false to refuse names outright."
        ),
    )
    # Two timeouts, and the order between them matters. `scan_host_timeout_seconds`
    # is nmap's own graceful give-up: it stops probing and writes the XML it has.
    # `scan_timeout_seconds` is our hard kill, which produces *no* output at all.
    # The first must be comfortably smaller than the second, or a slow host yields
    # nothing rather than partial results - the validator below enforces it.
    #
    # Both defaults are sized for a real remote host rather than for loopback. A
    # `-Pn -sV` sweep across the internet is minutes, not the seconds it takes
    # against a service on the same machine.
    scan_timeout_seconds: float = Field(default=240.0, gt=0)
    scan_host_timeout_seconds: float = Field(
        default=180.0,
        gt=0,
        description="Passed to nmap as --host-timeout, so a slow host degrades to partial results.",
    )
    # A sweep is many hosts in one command, so it needs its own, longer budget -
    # `--host-timeout` still bounds each host individually, which is what keeps one
    # unresponsive address from consuming the whole sweep.
    scan_sweep_timeout_seconds: float = Field(default=900.0, gt=0)
    # Host discovery is a ping sweep with no service probing: seconds for a /24,
    # even across a slow link. Kept separate so the cheap phase cannot inherit the
    # expensive phase's patience and hide a network that is simply unreachable.
    scan_discovery_timeout_seconds: float = Field(default=180.0, gt=0)
    scan_timing_template: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = Field(
        default="T4",
        description=(
            "nmap timing template. T4 is the usual choice for a responsive network; "
            "drop to T2/T3 for a fragile target or a link that drops probes."
        ),
    )
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
    cve_request_interval_seconds: float = Field(
        default=0.35,
        ge=0,
        description=(
            "Minimum gap between outbound CVE requests. One assessment enriches every "
            "CVE its rules matched at once, and the public service answers 429 to a "
            "burst - which costs the enrichment on findings that are otherwise correct. "
            "Set to 0 for a provider with no rate limit, or raise it for a stricter one."
        ),
    )

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
    def _host_timeout_must_leave_room_to_write_output(self) -> Settings:
        """nmap has to give up before we kill it, or a slow scan returns nothing.

        Refused at startup rather than per-scan: the symptom of getting this wrong
        is an empty result on exactly the hosts that most needed scanning, which
        reads as "the host is clean" instead of "the scan was cut off".
        """
        if self.scan_host_timeout_seconds >= self.scan_timeout_seconds:
            msg = (
                f"SCAN_HOST_TIMEOUT_SECONDS ({self.scan_host_timeout_seconds:g}) must be "
                f"less than SCAN_TIMEOUT_SECONDS ({self.scan_timeout_seconds:g}). The "
                "first lets nmap stop and write partial results; the second kills it "
                "and discards everything."
            )
            raise ValueError(msg)
        return self

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
