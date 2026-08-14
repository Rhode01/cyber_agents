"""What this server is allowed to reach, for two opposite reasons.

This module holds **two policies that are exact inverses**, and they sit together so the
next person to touch either can see that the difference is deliberate:

``check_target`` - **scanning.** A tool that runs nmap against a caller-supplied string is
a scanning proxy. Left open it would let anyone who can reach the MCP port scan the
internet from this host's address, and "the agent asked me to" is not authorisation. So
only addresses inside the configured allowlist are permitted, and everything else is
refused. The default allowlist is the private ranges; putting a client's own servers in
scope is an explicit act by whoever runs this service, which is where that decision
belongs.

``check_fetch_target`` - **phishing link inspection.** Here the danger runs the other way.
The URL comes from a hostile email, so the risk is that it points *inward*: at loopback, at
a private service, at the cloud metadata endpoint. So only public addresses are permitted,
and private ones are refused.

Both default to refusing. They disagree about which direction is dangerous because they
are protecting against different things - one protects the internet from this host, the
other protects this host from the internet.

Both resolve hostnames, and for the same reason: a name is not a scope decision, an
address is.

* Scanning resolves, then requires **every** address the name returned to be inside the
  configured allowlist, and hands the scanner one of those addresses rather than the name.
  Resolution therefore cannot widen scope - it can only map a name onto addresses an
  operator has already authorised - and because the scan targets the vetted address, DNS
  cannot change the target between the check and the scan.

  This used to refuse hostnames outright, which was safe but wrong for the actual job:
  a client asks for their server by name, and telling them to look up its address first
  does not make anything safer. What makes it safe is that the allowlist is still the
  only gate.
* Fetching resolves because a hostile URL is a hostname whose address is the whole
  question. It checks every address returned, on every redirect hop. The residual gap -
  the address can change between the check and the connection - is named in ``fetch.py``.
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
    """Whether a target may be scanned, and why not when it may not.

    ``target`` is what the scanner should be given - a vetted address, or a local
    name that is allowed by name. ``requested`` is what the caller asked for, which
    differs whenever a hostname was resolved, and is worth reporting back so an
    operator can see that ``c9.example.com`` became ``203.0.113.10``.
    """

    allowed: bool
    target: str
    reason: str = ""
    requested: str = ""
    addresses: tuple[str, ...] = ()

    @property
    def is_ipv6(self) -> bool:
        """Does the scanner need to be told to speak IPv6?"""
        try:
            return ipaddress.ip_address(self.target).version == 6
        except ValueError:
            return False

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "reason": self.reason,
            "requested": self.requested or self.target,
            "addresses": list(self.addresses),
        }


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


def _in_scope(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, allowed: list[Network]
) -> bool:
    return any(address in network for network in allowed)


def _preferred_address(
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Which address to actually scan when a name returned several.

    IPv4 first: it is what a scanner reaches by default, and a host that answers
    on both is the same host either way.
    """
    for address in addresses:
        if address.version == 4:
            return address
    return addresses[0]


def _decide_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowed: list[Network],
    *,
    requested: str,
) -> TargetDecision:
    """Apply the allowlist to one literal address."""
    if _in_scope(address, allowed):
        return TargetDecision(
            True, str(address), requested=requested, addresses=(str(address),)
        )
    return TargetDecision(
        False,
        str(address),
        f"{address} is outside the configured scan allowlist. Set "
        "SCAN_ALLOWED_TARGETS to include it if this host is in scope for testing.",
        requested=requested,
        addresses=(str(address),),
    )


async def _decide_hostname(host: str, allowed: list[Network]) -> TargetDecision:
    """Resolve a name and apply the allowlist to every address it returned."""
    try:
        resolved = await resolve_addresses(host)
    except OSError as err:
        return TargetDecision(False, host, f"{host} did not resolve: {err}", requested=host)
    if not resolved:
        return TargetDecision(False, host, f"{host} resolved to no addresses.", requested=host)

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_address in resolved:
        try:
            addresses.append(ipaddress.ip_address(raw_address))
        except ValueError:
            return TargetDecision(
                False,
                host,
                f"{host} resolved to an unreadable address {raw_address!r}.",
                requested=host,
                addresses=tuple(resolved),
            )

    seen = tuple(str(address) for address in addresses)
    outside = [address for address in addresses if not _in_scope(address, allowed)]
    if outside:
        listed = ", ".join(str(address) for address in outside)
        return TargetDecision(
            False,
            host,
            f"{host} resolves to {listed}, which is outside the configured scan "
            "allowlist. Every address a name resolves to has to be in scope, because "
            "which one the scanner reaches is not ours to choose. Set "
            "SCAN_ALLOWED_TARGETS to include them if this host is in scope for testing.",
            requested=host,
            addresses=seen,
        )

    return TargetDecision(
        True, str(_preferred_address(addresses)), requested=host, addresses=seen
    )


async def check_target(
    raw: str, allowed: list[Network], *, resolve: bool = True
) -> TargetDecision:
    """Decide whether ``raw`` may be scanned, and what the scanner should be given.

    Args:
        raw: Whatever the caller supplied - an address, a name, or a URL.
        allowed: The configured scan allowlist. This is the only gate; resolution
            does not widen it.
        resolve: Look up hostnames. Turning this off restores the older behaviour
            of refusing every name, for a deployment that wants addresses only.
    """
    target = normalize_target(raw)
    if not target:
        return TargetDecision(False, raw, "No target was supplied.")

    lowered = target.lower()
    if lowered in _LOCAL_HOSTNAMES or lowered.endswith(_LOCAL_SUFFIXES):
        # Allowed by name, and deliberately not resolved: these names mean "this
        # machine or this network" by definition, and several of them (.internal,
        # .local) commonly do not resolve at all.
        return TargetDecision(True, target, requested=target)

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        if not resolve:
            return TargetDecision(
                False,
                target,
                f"{target!r} is a hostname and hostname resolution is disabled on this "
                "server. Supply an IP address inside the configured scan allowlist, or "
                "set SCAN_RESOLVE_HOSTNAMES=true.",
                requested=target,
            )
        return await _decide_hostname(target, allowed)

    return _decide_address(address, allowed, requested=target)


# ---------------------------------------------------------------------------
# Sweeping a whole range.
# ---------------------------------------------------------------------------

# How many addresses one sweep may cover. This is a *runtime* bound, not an
# authorisation one - a scope entry may legitimately be a /16, but sweeping 65,536
# addresses is days of scanning, so the two limits are deliberately different
# numbers with different reasons. The refusal message has to say which one it is,
# or an operator reads "too big" as "not authorised" and adds the range again.
MAX_SWEEP_ADDRESSES: Final = 1024  # a /22

# Ranges no attestation covers. Duplicated from ``cyber_contracts.scope`` rather
# than imported: this module has no dependency on the contracts package (see
# app/security.py, which defines its own header constant for the same reason), and
# a scanner that trusts the caller to have already checked is a scanner with no
# check. The important entry is link-local, which holds the cloud instance-metadata
# endpoint at 169.254.169.254.
FORBIDDEN_SWEEP_NETWORKS: Final = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
)


@dataclass(frozen=True, slots=True)
class RangeDecision:
    """Whether a whole range may be swept, and why not when it may not."""

    allowed: bool
    network: str
    reason: str = ""
    address_count: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "network": self.network,
            "reason": self.reason,
            "address_count": self.address_count,
        }


def _covers(network: Network, entry: Network) -> bool:
    """Is ``network`` wholly inside ``entry``?

    ``subnet_of`` raises on a version mismatch, so that is checked first rather
    than caught - an IPv4 range is not partially inside an IPv6 grant.
    """
    if network.version != entry.version:
        return False
    return network.subnet_of(entry)  # type: ignore[arg-type]


def check_range(raw: str, allowed: list[Network]) -> RangeDecision:
    """Decide whether an entire range may be swept.

    The rule that matters is **subset, not overlap**. A range that is half inside an
    authorised network is refused outright, because sweeping it would touch hosts
    nobody authorised - the same reasoning ``_decide_hostname`` applies to a name
    resolving to several addresses.

    Args:
        raw: A CIDR range, e.g. ``192.168.1.0/24``. A bare address is accepted and
            treated as a single-host range.
        allowed: The configured allowlist unioned with operator-managed scope.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return RangeDecision(False, "", "No range was supplied.")

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return RangeDecision(
            False,
            candidate,
            f"{candidate!r} is not an IP range. Use CIDR notation, for example "
            "192.168.1.0/24, or a single address.",
        )

    for forbidden in FORBIDDEN_SWEEP_NETWORKS:
        if network.version == forbidden.version and network.overlaps(forbidden):
            return RangeDecision(
                False,
                str(network),
                f"{network} overlaps {forbidden}, which is never sweepable. That range "
                "holds the cloud instance-metadata endpoint and other addresses that "
                "are not any client's to authorise.",
            )

    if network.num_addresses > MAX_SWEEP_ADDRESSES:
        return RangeDecision(
            False,
            str(network),
            f"{network} covers {network.num_addresses:,} addresses and one sweep may "
            f"cover at most {MAX_SWEEP_ADDRESSES:,}. This is a limit on how long a "
            "single scan may run, not on what you are authorised to scan - split it "
            "into smaller ranges and sweep them separately.",
        )

    if not any(_covers(network, entry) for entry in allowed):
        return RangeDecision(
            False,
            str(network),
            f"{network} is not wholly inside any authorised range. A range that is "
            "only partly in scope is out of scope, because a sweep would reach hosts "
            "nobody authorised. Add it under Scan scope if this network is in scope "
            "for testing.",
        )

    return RangeDecision(True, str(network), address_count=network.num_addresses)


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


async def resolve_addresses(host: str) -> list[str]:
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
        addresses = await resolve_addresses(host)
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
