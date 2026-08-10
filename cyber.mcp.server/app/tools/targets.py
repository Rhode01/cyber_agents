"""What this server is allowed to scan.

A tool that runs nmap against a caller-supplied string is a scanning proxy. Left
open it would let anyone who can reach the MCP port scan the internet from this
host's address, and "the agent asked me to" is not authorisation. So the target
is checked against an explicit allowlist before any scanner starts, and the
default allowlist is the private address space only.

Two deliberate refusals:

* **No DNS resolution.** Resolving a hostname to decide whether it is in scope
  hands the decision to whoever controls the DNS answer, and the answer can
  change between the check and the scan. A hostname is only allowed when it is
  explicitly listed, never because it currently resolves somewhere permitted.
* **No partial credit.** An unparseable target is refused, not scanned.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

_LOCAL_HOSTNAMES: Final = frozenset({"localhost"})
_LOCAL_SUFFIXES: Final = (".localhost", ".local", ".localdomain", ".internal")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class TargetDecision:
    """Whether a target may be scanned, and why not when it may not."""

    allowed: bool
    target: str
    reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {"allowed": self.allowed, "target": self.target, "reason": self.reason}


def parse_networks(entries: list[str]) -> list[Network]:
    """Parse the configured CIDR allowlist, skipping anything unreadable.

    A malformed entry is dropped rather than raising: one typo in an env var
    should not stop the whole service from starting, and the effect of dropping
    it is a *narrower* allowlist, which fails in the safe direction.
    """
    networks: list[Network] = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            continue
    return networks


def normalize_target(raw: str) -> str:
    """Strip scheme, credentials, port and path down to a bare host.

    Callers hand over whatever they have - ``https://10.0.0.5:8443/status`` as
    often as ``10.0.0.5``.
    """
    target = raw.strip()
    if not target:
        return ""
    if "//" in target:
        target = urlparse(target).netloc or target
    target = target.rpartition("@")[2]
    if target.startswith("["):  # bracketed IPv6 literal, optionally with a port
        return target.partition("]")[0].lstrip("[")
    # Only strip a trailing :port when it is unambiguous; a bare IPv6 literal has
    # many colons and no port.
    if target.count(":") == 1:
        target = target.partition(":")[0]
    return target


def check_target(raw: str, allowed: list[Network]) -> TargetDecision:
    """Decide whether ``raw`` may be scanned."""
    target = normalize_target(raw)
    if not target:
        return TargetDecision(False, raw, "No target was supplied.")

    lowered = target.lower()
    if lowered in _LOCAL_HOSTNAMES or lowered.endswith(_LOCAL_SUFFIXES):
        return TargetDecision(True, target, "")

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return TargetDecision(
            False,
            target,
            f"{target!r} is a hostname. Only IP addresses inside the configured scan "
            "allowlist, and explicitly local names, can be scanned - resolving a name "
            "to decide scope would let DNS choose the target.",
        )

    if any(address in network for network in allowed):
        return TargetDecision(True, str(address), "")

    return TargetDecision(
        False,
        str(address),
        f"{address} is outside the configured scan allowlist. Set "
        "SCAN_ALLOWED_TARGETS to include it if this host is in scope for testing.",
    )
