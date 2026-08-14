"""Authorised scan scope.

Which hosts this platform is permitted to scan, as data an operator manages,
rather than as a config value that needs a redeploy.

Three properties this contract exists to hold:

**Scope is addresses, not names.** A user may type a hostname - that is how people
refer to their servers - but what gets stored is the address it resolved to, and
what gets checked at scan time is the address. Storing the name would mean whoever
controls DNS decides what this platform scans, which is the thing the target policy
exists to prevent. The name is kept alongside, for display, and is never consulted.

**Scope is an attestation, not a preference.** Adding an entry is a claim that the
operator owns the host or holds authorisation to test it, and ``authorized_by`` and
``note`` record who made that claim. A scanning platform with no answer to "who said
we could scan this" is a liability, and the answer has to be written down at the
moment the claim is made rather than reconstructed later.

**Scope is bounded.** ``MAX_SCOPE_ADDRESSES`` caps how much one entry may authorise,
so a mistyped prefix widens scope by a subnet rather than by the internet.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

# The largest range one entry may authorise: a /16, i.e. 65,536 addresses. Wide
# enough for a real corporate network, narrow enough that "/0" or a fat-fingered
# prefix is refused rather than silently authorising everything.
MAX_SCOPE_ADDRESSES: Final = 1 << 16

# Ranges that may never be added, whatever anyone attests to. The link-local block
# holds the cloud instance-metadata endpoint (169.254.169.254): a scan reaching it
# reads this platform's own credentials, and no client authorisation covers that.
FORBIDDEN_SCOPE_NETWORKS: Final = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
)


def normalize_scope_target(raw: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse one scope entry into a network, or raise ``ValueError`` saying why not.

    A bare address becomes a host network (``/32``, ``/128``), so every entry is
    one shape and the scan-time check is a single ``address in network``.
    """
    candidate = raw.strip()
    if not candidate:
        msg = "No target was supplied."
        raise ValueError(msg)

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        msg = (
            f"{candidate!r} is not an IP address or CIDR range. Enter an address "
            "like 203.0.113.10, or a range like 203.0.113.0/24."
        )
        raise ValueError(msg) from exc

    if network.num_addresses > MAX_SCOPE_ADDRESSES:
        msg = (
            f"{network} covers {network.num_addresses:,} addresses, more than the "
            f"{MAX_SCOPE_ADDRESSES:,} one entry may authorise. Add the specific "
            "subnets you own instead of one range that spans them."
        )
        raise ValueError(msg)

    for forbidden in FORBIDDEN_SCOPE_NETWORKS:
        if network.version == forbidden.version and network.overlaps(forbidden):
            msg = (
                f"{network} overlaps {forbidden}, which can never be added to scope. "
                "That range holds the cloud instance-metadata endpoint and other "
                "addresses that are not any client's to authorise."
            )
            raise ValueError(msg)

    return network


class ScanScopeCreate(BaseModel):
    """A request to authorise scanning of one host or range."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        min_length=1,
        max_length=255,
        description=(
            "A hostname, IP address, or CIDR range. A hostname is resolved and its "
            "addresses are what get stored - the name itself is never consulted at "
            "scan time."
        ),
    )
    label: str = Field(
        default="",
        max_length=120,
        description="What this host is, in the operator's own words.",
    )
    authorized_by: str = Field(
        min_length=1,
        max_length=120,
        description="Who attests that this host is in scope. Recorded, never verified.",
    )
    note: str = Field(
        default="",
        max_length=2000,
        description="Why it is in scope - a contract reference, a ticket, an owner.",
    )

    @field_validator("target", "label", "authorized_by", "note")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class ScanScopeEntry(BaseModel):
    """One authorised range, as stored.

    ``network`` is what the scan-time check uses. ``requested`` is what the operator
    typed, kept only so the list reads back the way they entered it.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    network: str
    requested: str
    label: str
    authorized_by: str
    note: str
    active: bool
    created_at: datetime
    updated_at: datetime


class ScanScopeList(BaseModel):
    """Every scope entry, newest first."""

    items: list[ScanScopeEntry]
    total: int


class ScanScopeNetworks(BaseModel):
    """Just the networks, for the MCP server's scan-time check.

    Deliberately separate from ``ScanScopeList``: the scanner needs the addresses
    and nothing else, and an endpoint that returns only those is one that cannot
    leak an operator's notes to a service that has no use for them.
    """

    networks: list[str]
