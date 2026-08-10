"""The discovery report contract shared by the backend and the ai.engine.

Discovery is the network phase that feeds the pipeline: enumerate the connected
interfaces, take the current device's own addresses from them (plus loopback,
so local services are reachable), and probe which of those addresses answer on
common web ports. The web hosts that come back are then handed to the web-app
agents (nuclei, nmap) as scan targets. A light nmap ``-sV`` pass over the same
addresses fills the ``services`` list with per-port service/version data, which
is what the "Services Active" page renders.

There is no subnet sweep: the machine running the pipeline is itself the target,
so its neighbours are never pinged.

Nothing in this payload is a finding yet: it is reconnaissance output, and every
field is untrusted data. The backend proxies it to the frontend verbatim.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class InterfaceInfo(BaseModel):
    """One connected network interface that has an IPv4 address."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Interface name, e.g. eth0.")
    ip: str = Field(description="IPv4 address assigned to the interface.")
    prefix: int = Field(ge=0, le=32, description="CIDR prefix length.")
    subnet: str = Field(description="The interface's subnet, e.g. 192.168.1.0/24.")


class WebHost(BaseModel):
    """A discovered host that answers on at least one common web port."""

    model_config = ConfigDict(extra="forbid")

    host: str = Field(description="IP address (or hostname) of the web host.")
    ports: list[int] = Field(default_factory=list, description="Open web ports found.")
    urls: list[str] = Field(default_factory=list, description="Candidate URLs to scan.")


class ServicePort(BaseModel):
    """One detected service on one address, from the nmap ``-sV`` pass.

    The string fields come straight from nmap output and are untrusted.
    """

    model_config = ConfigDict(extra="forbid")

    host: str = Field(description="Address the service listens on.")
    port: int = Field(ge=1, le=65535, description="Port number.")
    protocol: str = Field(default="tcp", max_length=8, description="tcp or udp.")
    service: str | None = Field(default=None, description="Nmap service name, e.g. ssh.")
    product: str | None = Field(default=None, description="Product banner, e.g. OpenSSH.")
    version: str | None = Field(default=None, description="Product version, e.g. 7.2.")
    extra_info: str | None = Field(default=None, description="Additional banner text.")


class DiscoveryReport(BaseModel):
    """The outcome of one network discovery pass."""

    model_config = ConfigDict(extra="forbid")

    interfaces: list[InterfaceInfo] = Field(
        default_factory=list, description="Connected IPv4 interfaces."
    )
    subnets: list[str] = Field(
        default_factory=list, description="Subnets derived from the interfaces."
    )
    live_hosts: list[str] = Field(
        default_factory=list, description="The device's own addresses (interfaces plus loopback)."
    )
    web_hosts: list[WebHost] = Field(
        default_factory=list, description="Live hosts that run a web service."
    )
    services: list[ServicePort] = Field(
        default_factory=list,
        description="Services detected by nmap -sV on the device's own addresses.",
    )
    duration_seconds: float = Field(default=0.0, description="Total discovery duration.")
    notes: list[str] = Field(
        default_factory=list, description="Human-readable notes about what ran or was skipped."
    )


__all__ = ["DiscoveryReport", "InterfaceInfo", "ServicePort", "WebHost"]
