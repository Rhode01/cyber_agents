"""Sweeping a network range instead of scanning one host.

The intake node grew a second path: a target with a prefix is discovered first
(which addresses answer at all) and then service-scanned in one pass. What is
tested here is the branch and its honesty — that "nothing was alive" does not look
like "the scan broke", and that a truncated sweep says so.

Everything *after* intake is deliberately untested here, because nothing after it
changed: the nmap parser already iterates every ``<host>`` element and each
observation already carries its own address. That property is asserted once, at
the bottom, so a future change to the parser cannot quietly break sweeps.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from app.agents.vulnerability import nodes
from app.agents.vulnerability.nodes import MAX_SWEEP_HOSTS, _is_range, intake
from app.mcp import HOST_DISCOVERY_TOOL, NMAP_SCAN_TOOL, SWEEP_SCAN_TOOL

SWEEP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh" product="OpenSSH" version="7.2"/></port></ports></host>
  <host><status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="3306"><state state="open"/>
      <service name="mysql" product="MySQL" version="5.5.62"/></port></ports></host>
</nmaprun>"""


class _FakeTools:
    """Stands in for a live MCP session offering the sweep tools."""

    def __init__(
        self,
        *,
        discovery: dict[str, Any] | None = None,
        sweep: dict[str, Any] | None = None,
        offers: tuple[str, ...] = (HOST_DISCOVERY_TOOL, SWEEP_SCAN_TOOL, NMAP_SCAN_TOOL),
    ) -> None:
        self.discovery = discovery or {}
        self.sweep = sweep or {}
        self.offers = offers
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def has(self, tool: str) -> bool:
        return tool in self.offers

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, arguments))
        return self.discovery if tool == HOST_DISCOVERY_TOOL else self.sweep


def _install(monkeypatch: pytest.MonkeyPatch, tools: _FakeTools | None) -> None:
    @asynccontextmanager
    async def _open(*_args: object, **_kwargs: object) -> AsyncIterator[_FakeTools | None]:
        yield tools

    monkeypatch.setattr(nodes, "open_tools", _open)


def _discovered(hosts: list[str], *, total: int = 256) -> dict[str, Any]:
    return {
        "ok": True,
        "output": "<nmaprun/>",
        "meta": {"live_hosts": hosts, "live_count": len(hosts), "addresses_in_range": total},
    }


# ---------------------------------------------------------------------------
# Which targets take the sweep path.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["192.168.1.0/24", "10.0.0.0/28", "2001:db8::/120"])
def test_a_prefixed_target_is_a_range(target: str) -> None:
    assert _is_range(target) is True


@pytest.mark.parametrize(
    "target",
    ["192.168.1.5", "server.client.com", "", "not-a-target", "192.168.1.0/33", "10.0.0.1:22"],
)
def test_everything_else_is_a_single_host(target: str) -> None:
    """A bare address must not take the sweep path.

    It parses as a /32, so "does it parse as a network" would send every ordinary
    scan through two phases and lose the hostname resolution the single-host path
    has. The prefix is the signal.
    """
    assert _is_range(target) is False


# ---------------------------------------------------------------------------
# The two-phase sweep.
# ---------------------------------------------------------------------------


async def test_a_range_is_discovered_then_only_live_hosts_are_scanned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reason the cheap phase exists: 2 hosts scanned, not 256."""
    tools = _FakeTools(
        discovery=_discovered(["192.168.1.1", "192.168.1.50"]),
        sweep={"ok": True, "output": SWEEP_XML, "meta": {"hosts_scanned": 2}},
    )
    _install(monkeypatch, tools)

    result = await intake({"asset": "192.168.1.0/24", "source": "nmap"})

    assert [tool for tool, _ in tools.calls] == [HOST_DISCOVERY_TOOL, SWEEP_SCAN_TOOL]
    assert tools.calls[1][1]["hosts"] == ["192.168.1.1", "192.168.1.50"]
    assert result["raw_input"] == SWEEP_XML
    assert result["scan_info"]["status"] == "swept"
    assert result["scan_info"]["hosts_scanned"] == 2


async def test_a_single_host_target_still_takes_the_original_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _FakeTools(sweep={"ok": True, "output": SWEEP_XML, "meta": {}})
    _install(monkeypatch, tools)

    result = await intake({"asset": "192.168.1.50", "source": "nmap"})

    assert [tool for tool, _ in tools.calls] == [NMAP_SCAN_TOOL]
    assert result["scan_info"]["status"] == "scanned"


async def test_an_empty_range_is_reported_as_no_hosts_not_as_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The distinction that matters in a report.

    "The range was reachable and nothing answered" and "the scan broke" produce the
    same absence of findings, and must not produce the same message — one is a
    result, the other is a gap.
    """
    tools = _FakeTools(discovery=_discovered([]))
    _install(monkeypatch, tools)

    result = await intake({"asset": "192.168.1.0/24", "source": "nmap"})

    assert result["scan_info"]["status"] == "no-live-hosts"
    assert result["scan_info"]["addresses_in_range"] == 256
    assert "raw_input" not in result
    # The expensive phase never ran: there was nothing to run it against.
    assert [tool for tool, _ in tools.calls] == [HOST_DISCOVERY_TOOL]


async def test_a_refused_range_surfaces_the_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """An out-of-scope range must say so, not report an empty network."""
    tools = _FakeTools(
        discovery={
            "ok": False,
            "error": "192.168.0.0/23 is not wholly inside any authorised range.",
            "meta": {"refused": True},
        }
    )
    _install(monkeypatch, tools)

    result = await intake({"asset": "192.168.0.0/23", "source": "nmap"})

    assert result["scan_info"]["status"] == "scan-failed"
    assert "not wholly inside" in result["scan_info"]["error"]


async def test_a_sweep_larger_than_the_cap_reports_that_it_was_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A report covering 64 of 200 hosts must not read as covering the network."""
    many = [f"10.20.0.{index}" for index in range(1, 101)]
    tools = _FakeTools(
        discovery=_discovered(many, total=1024),
        sweep={"ok": True, "output": SWEEP_XML, "meta": {}},
    )
    _install(monkeypatch, tools)

    result = await intake({"asset": "10.20.0.0/22", "source": "nmap"})

    assert len(tools.calls[1][1]["hosts"]) == MAX_SWEEP_HOSTS
    assert result["scan_info"]["truncated"] is True
    assert result["scan_info"]["live_hosts"] == 100
    assert result["scan_info"]["hosts_scanned"] == MAX_SWEEP_HOSTS


async def test_an_untruncated_sweep_says_so_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """`truncated` is always present, so a reader never has to infer it from absence."""
    tools = _FakeTools(
        discovery=_discovered(["192.168.1.1"]),
        sweep={"ok": True, "output": SWEEP_XML, "meta": {}},
    )
    _install(monkeypatch, tools)

    result = await intake({"asset": "192.168.1.0/24", "source": "nmap"})

    assert result["scan_info"]["truncated"] is False


async def test_a_missing_sweep_tool_is_reported_rather_than_silently_downgraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An older MCP server must not make a range scan look like a clean network."""
    _install(monkeypatch, _FakeTools(offers=(NMAP_SCAN_TOOL,)))

    result = await intake({"asset": "192.168.1.0/24", "source": "nmap"})

    assert result["scan_info"]["status"] == "scanner-unavailable"
    assert "network range" in result["scan_info"]["error"]


async def test_no_mcp_session_at_all_is_still_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, None)

    result = await intake({"asset": "192.168.1.0/24", "source": "nmap"})

    assert result["scan_info"]["status"] == "scanner-unavailable"


# ---------------------------------------------------------------------------
# The property the whole design leans on.
# ---------------------------------------------------------------------------


def test_multi_host_xml_becomes_one_observation_set_per_host() -> None:
    """Nothing downstream of intake needed changing, and this is why.

    If a future parser change collapsed multi-host XML to a single host, sweeps
    would silently attribute every finding to one address. That would look like a
    working sweep and be worthless, so it is asserted rather than assumed.
    """
    from app.agents.vulnerability.sources import from_raw

    observations = from_raw("nmap", SWEEP_XML)

    assert observations.parsed is True
    assert {observation.host for observation in observations.observations} == {
        "192.168.1.1",
        "192.168.1.50",
    }
