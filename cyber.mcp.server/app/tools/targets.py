"""What this server is allowed to reach, for two opposite reasons.

This module holds **two policies that are exact inverses**, and they sit together so the
next person to touch either can see that the difference is deliberate:

``check_target`` - **scanning.** A tool that runs nmap against a caller-supplied string is
a scanning proxy. Left open it would let anyone who can reach the MCP port scan the
internet from this host's address, and "the agent asked me to" is not authorisation. So
only private, explicitly allowlisted addresses are permitted, and public ones are refused.

``check_fetch_target`` - **phishing link inspection.** Here the danger runs the other way.
The URL comes from a hostile email, so the risk is that it points *inward*: at loopback, at
a private service, at the cloud metadata endpoint. So only public addresses are permitted,
and private ones are refused.

Both default to refusing. They disagree about which direction is dangerous because they
are protecting against different things - one protects the internet from this host, the
other protects this host from the internet.

They also differ on DNS, and that is deliberate too:

* Scanning does **not** resolve. Resolving a hostname to decide scope hands the decision
  to whoever controls the DNS answer, and the answer can change between the check and the
  scan. A hostname is allowed only when explicitly listed.
* Fetching **must** resolve, because a hostile URL is a hostname whose address is the whole
  question. So it resolves and checks every address returned, on every redirect hop. The
  residual gap - the address can change between the check and the connection - is named in
  ``fetch.py``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
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


# ---------------------------------------------------------------------------
# The inverse policy: fetching a link out of a hostile message.
# ---------------------------------------------------------------------------

FETCHABLE_SCHEMES: Final = frozenset({"http", "https"})


@dataclass(frozen=True, slots=True)
class FetchDecision:
    """Whether a URL may be fetched, and which addresses were vetted."""

    allowed: bool
    host: str
    addresses: tuple[str, ...] = ()
    reason: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "host": self.host,
            "addresses": list(self.addresses),
            "reason": self.reason,
        }


def _is_forbidden_for_fetch(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Why this address must not be fetched, or "" if it may be.

    Every category here is somewhere a phishing URL should never be able to send us.
    ``169.254.0.0/16`` is covered by ``is_link_local`` and is the important one: it holds
    the cloud instance-metadata endpoint, and a fetch that reaches it can read this
    host's own credentials.
    """
    if address.is_unspecified:
        return "the unspecified address"
    if address.is_loopback:
        return "a loopback address"
    if address.is_link_local:
        return "a link-local address (this range holds the cloud metadata endpoint)"
    if address.is_private:
        return "a private address"
    if address.is_reserved:
        return "a reserved address"
    if address.is_multicast:
        return "a multicast address"

    # No explicit unwrapping of IPv4-mapped (::ffff:10.0.0.5) or 6to4 (2002::/16)
    # addresses, because the checks above already cover them. Verified against Python
    # 3.12's ipaddress rather than assumed - it evaluates the embedded v4 address, so
    # ::ffff:10.0.0.5 reports is_private, ::ffff:169.254.169.254 reports is_link_local,
    # and the whole 2002::/16 range reports is_private regardless of what it wraps.
    #
    # Unwrapping by hand was written here first and deleted as unreachable. The tests
    # still assert that these forms are refused, so if a future Python narrows those
    # properties the gap shows up as a failure rather than as a silent bypass.
    return ""


async def _resolve(host: str) -> list[str]:
    """Every address ``host`` currently resolves to.

    Uses the loop's executor rather than blocking it. An IP literal short-circuits, so a
    caller passing one does not pay for a resolver round trip.
    """
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        return [host.strip("[]")]

    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    # dict.fromkeys rather than set(), so the order is stable and the log reads the same
    # way twice for the same host.
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def check_fetch_target(raw: str) -> FetchDecision:
    """Decide whether ``raw`` may be fetched, resolving it first.

    Refuses unless **every** address the host resolves to is public. All of them, not the
    first: a hostname that returns one public and one loopback address would otherwise be
    fetchable, and which one the client connects to is not ours to predict.

    Args:
        raw: An absolute http or https URL.

    Returns:
        A ``FetchDecision``. When allowed, ``addresses`` holds the vetted addresses.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return FetchDecision(False, "", reason="No URL was supplied.")

    try:
        parts = urlparse(candidate)
    except ValueError as err:
        return FetchDecision(False, "", reason=f"The URL could not be parsed: {err}")

    scheme = (parts.scheme or "").lower()
    if scheme not in FETCHABLE_SCHEMES:
        listed = ", ".join(sorted(FETCHABLE_SCHEMES))
        return FetchDecision(
            False,
            "",
            reason=f"Only {listed} URLs can be fetched, not {scheme or 'a relative URL'}.",
        )

    try:
        host = parts.hostname
    except ValueError as err:
        return FetchDecision(False, "", reason=f"The URL has an unusable host: {err}")
    if not host:
        return FetchDecision(False, "", reason="The URL has no host.")

    lowered = host.lower()
    # Refused before resolution: these names are local by definition, and asking a
    # resolver about them only invites a surprising answer.
    if lowered in _LOCAL_HOSTNAMES or lowered.endswith(_LOCAL_SUFFIXES):
        return FetchDecision(
            False, host, reason=f"{host} names this machine or a local network."
        )

    try:
        addresses = await _resolve(host)
    except OSError as err:
        return FetchDecision(False, host, reason=f"{host} did not resolve: {err}")

    if not addresses:
        return FetchDecision(False, host, reason=f"{host} resolved to no addresses.")

    for raw_address in addresses:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            return FetchDecision(
                False, host, reason=f"{host} resolved to an unreadable address {raw_address!r}."
            )
        forbidden = _is_forbidden_for_fetch(address)
        if forbidden:
            return FetchDecision(
                False,
                host,
                addresses=tuple(addresses),
                reason=(
                    f"{host} resolves to {raw_address}, which is {forbidden}. Fetching it "
                    f"would point this server at its own network."
                ),
            )

    return FetchDecision(True, host, addresses=tuple(addresses))
