"""Whether a whole range may be swept.

This is the gate that decides how many machines a single command touches, so it
gets the same attention as `check_target`. The rule under test throughout is
**subset, not overlap**: a range half inside an authorised network is refused,
because sweeping it would reach hosts nobody attested to.

Two limits are deliberately different numbers for different reasons, and the tests
keep them apart: scope may authorise a /16, but one sweep may cover a /22. Confusing
them is how an operator ends up re-adding a range that was never the problem.
"""

from __future__ import annotations

import pytest

from app.server import _live_hosts
from app.tools import MAX_SWEEP_ADDRESSES, check_range, parse_networks

AUTHORISED = parse_networks(["192.168.1.0/24", "10.20.0.0/22", "2001:db8::/64"])


def test_a_range_wholly_inside_an_authorised_network_is_swept() -> None:
    decision = check_range("192.168.1.0/24", AUTHORISED)

    assert decision.allowed is True
    assert decision.network == "192.168.1.0/24"
    assert decision.address_count == 256


def test_a_smaller_range_inside_an_authorised_one_is_swept() -> None:
    """Authorising a /24 authorises everything within it, not only the exact match."""
    decision = check_range("192.168.1.0/28", AUTHORISED)

    assert decision.allowed is True
    assert decision.address_count == 16


def test_a_bare_address_is_treated_as_a_single_host_range() -> None:
    decision = check_range("192.168.1.50", AUTHORISED)

    assert decision.allowed is True
    assert decision.network == "192.168.1.50/32"
    assert decision.address_count == 1


def test_a_range_only_partly_authorised_is_refused_entirely() -> None:
    """The property this policy exists for.

    192.168.0.0/23 covers 192.168.0.x and 192.168.1.x. Only the second is
    authorised. Overlap is not enough - sweeping it would touch 256 addresses
    nobody attested to.
    """
    decision = check_range("192.168.0.0/23", AUTHORISED)

    assert decision.allowed is False
    assert "wholly inside" in decision.reason


def test_a_range_outside_every_authorised_network_is_refused() -> None:
    decision = check_range("203.0.113.0/24", AUTHORISED)

    assert decision.allowed is False
    assert "not wholly inside any authorised range" in decision.reason


def test_an_empty_allowlist_permits_nothing() -> None:
    assert check_range("192.168.1.0/24", []).allowed is False


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "nonsense", "192.168.1.0/33", "192.168.1.0-50", "example.com"],
)
def test_unreadable_ranges_are_refused_with_a_reason(raw: str) -> None:
    decision = check_range(raw, AUTHORISED)

    assert decision.allowed is False
    assert decision.reason, "a refusal must say why"


def test_a_hostname_is_not_a_range() -> None:
    """Names are resolved for single targets, never for sweeps.

    A name maps to a handful of addresses; a sweep needs a contiguous block. Letting
    DNS describe a range would be the DNS-decides-scope problem at 1024x the size.
    """
    decision = check_range("server.client.com", AUTHORISED)

    assert decision.allowed is False
    assert "not an IP range" in decision.reason


# ---------------------------------------------------------------------------
# The two limits, kept apart.
# ---------------------------------------------------------------------------


def test_a_range_over_the_sweep_cap_is_refused_as_a_runtime_limit() -> None:
    """A /16 may be authorised, but one sweep may not cover it.

    The message has to say this is about how long a scan runs, not about
    authorisation - otherwise the operator adds the range to scope again and it
    fails identically the second time.
    """
    wide = parse_networks(["10.0.0.0/16"])

    decision = check_range("10.0.0.0/16", wide)

    assert decision.allowed is False
    assert "at most" in decision.reason
    assert "not on what you are authorised to scan" in decision.reason


def test_the_sweep_cap_boundary_is_a_slash_22() -> None:
    """Assert the boundary rather than assume it: /22 in, /21 out."""
    wide = parse_networks(["10.0.0.0/16"])

    assert check_range("10.0.0.0/22", wide).allowed is True
    assert check_range("10.0.0.0/21", wide).allowed is False
    assert MAX_SWEEP_ADDRESSES == 1024


# ---------------------------------------------------------------------------
# Ranges no attestation covers.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ["169.254.169.254", "169.254.0.0/24", "224.0.0.1", "0.0.0.0/24"],
)
def test_forbidden_ranges_are_refused_even_when_authorised(raw: str) -> None:
    """169.254.169.254 serves this platform's own cloud credentials.

    Checked here and not only in the scope form, because a scanner that trusts the
    caller to have already checked is a scanner with no check.
    """
    everything = parse_networks(["0.0.0.0/1", "128.0.0.0/1", "169.254.0.0/16", "224.0.0.0/4"])

    decision = check_range(raw, everything)

    assert decision.allowed is False
    assert "never sweepable" in decision.reason


# ---------------------------------------------------------------------------
# IPv6 does not leak across versions.
# ---------------------------------------------------------------------------


def test_an_ipv6_range_inside_an_ipv6_grant_is_swept() -> None:
    assert check_range("2001:db8::/120", AUTHORISED).allowed is True


def test_an_ipv4_range_is_not_covered_by_an_ipv6_grant() -> None:
    """`subnet_of` raises across versions; the check must not depend on that."""
    v6_only = parse_networks(["2001:db8::/32"])

    decision = check_range("192.168.1.0/24", v6_only)

    assert decision.allowed is False
    assert "not wholly inside" in decision.reason


# ---------------------------------------------------------------------------
# Reading the discovery scan's answer.
# ---------------------------------------------------------------------------

_DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.0/24">
  <host><status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/></host>
  <host><status state="down" reason="no-response"/>
    <address addr="192.168.1.2" addrtype="ipv4"/></host>
  <host><status state="up" reason="syn-ack"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>
  <host><status state="up" reason="nd-response"/>
    <address addr="2001:db8::5" addrtype="ipv6"/></host>
</nmaprun>"""


def test_only_hosts_reported_up_are_returned() -> None:
    """A down host in the range must not become a scan target."""
    assert _live_hosts(_DISCOVERY_XML) == ["192.168.1.1", "192.168.1.50", "2001:db8::5"]


def test_a_mac_address_is_never_mistaken_for_a_host() -> None:
    """`-sn` on a local segment reports a MAC alongside the IP; only the IP is a target."""
    assert all(":" not in host or host.startswith("2001") for host in _live_hosts(_DISCOVERY_XML))


@pytest.mark.parametrize("raw", ["", "not xml", "<nmaprun></nmaprun>", "<nmaprun><host/></nmaprun>"])
def test_unreadable_discovery_output_yields_no_hosts(raw: str) -> None:
    """Empty means "nothing to scan", which is the safe reading of a failed sweep."""
    assert _live_hosts(raw) == []
