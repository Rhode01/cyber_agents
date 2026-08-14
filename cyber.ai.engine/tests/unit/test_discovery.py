"""Discovery stage tests.

Nothing here talks to the network or a scanner binary: ``run_command`` is
patched with canned ``ip`` output, and the TCP probe is replaced with a
fixture. The parsing and filtering logic - the part that is ours - is what gets
exercised. Discovery targets the current device's own interface addresses; no
subnet sweep exists anymore.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from cyber_contracts import InterfaceInfo, ServicePort, WebHost

from app.api.v1.endpoints import discovery as discovery_endpoint
from app.discovery import tools


def test_parse_iface_line_parses_a_realistic_ip_line() -> None:
    line = "3: wlan0    inet 192.168.1.106/24 brd 192.168.1.255 scope global dynamic"

    iface = tools._parse_iface_line(line)

    assert iface is not None
    assert iface.name == "wlan0"
    assert iface.ip == "192.168.1.106"
    assert iface.prefix == 24
    assert iface.subnet == "192.168.1.0/24"


def test_parse_iface_line_ignores_non_inet_lines() -> None:
    assert tools._parse_iface_line("1: lo    inet6 ::1/128 scope host") is None
    assert tools._parse_iface_line("2: eth0    link/ether 00:11:22:33:44:55") is None
    assert tools._parse_iface_line("") is None


def test_url_for_port_maps_schemes() -> None:
    assert tools._url_for_port("10.0.0.5", 80) == "http://10.0.0.5"
    assert tools._url_for_port("10.0.0.5", 443) == "https://10.0.0.5"
    assert tools._url_for_port("10.0.0.5", 8080) == "http://10.0.0.5:8080"
    assert tools._url_for_port("10.0.0.5", 8443) == "https://10.0.0.5:8443"


async def test_list_interfaces_filters_loopback_host_routes_and_big_subnets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ip_output = "\n".join(
        [
            "1: lo    inet 127.0.0.1/8 scope host lo",
            "3: wlan0    inet 192.168.1.106/24 brd 192.168.1.255 scope global dynamic",
            "34: br-docker    inet 172.18.0.1/16 brd 172.18.255.255 scope global",
            "35: lan22    inet 10.20.0.1/22 brd 10.20.3.255 scope global",
            "52: wg0    inet 10.2.0.2/32 scope global wg0",
            "53: eth1    inet 169.254.1.5/16 brd 169.254.255.255 scope link",
            "54: huge0    inet 10.0.0.1/8 brd 10.255.255.255 scope global",
        ]
    )

    async def fake_run_command(command: list[str], **_: Any) -> tuple[int, str, str]:
        assert command[0] == "ip"
        return 0, fake_ip_output, ""

    monkeypatch.setattr(tools, "run_command", fake_run_command)

    interfaces = await tools.list_interfaces()

    names = [i.name for i in interfaces]
    assert names == ["wlan0", "lan22"]
    assert interfaces[0].subnet == "192.168.1.0/24"
    assert interfaces[1].subnet == "10.20.0.0/22"


async def test_interfaces_fall_back_to_powershell_when_ip_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows has no `ip`, and without this discovery only ever saw loopback.

    The symptom was a Services page that listed 127.0.0.1 and nothing else on
    every Windows host, with `ip is not installed on this host` in the log.
    """
    calls: list[str] = []

    async def fake_run_command(command: list[str], **_: Any) -> tuple[int, str, str]:
        calls.append(command[0])
        if command[0] == "ip":
            return -1, "", "ip is not installed on this host"
        return 0, (
            '[{"InterfaceAlias":"Wi-Fi","IPAddress":"192.168.1.106","PrefixLength":24},'
            '{"InterfaceAlias":"Loopback Pseudo-Interface 1","IPAddress":"127.0.0.1",'
            '"PrefixLength":8}]'
        ), ""

    monkeypatch.setattr(tools, "run_command", fake_run_command)

    interfaces = await tools.list_interfaces()

    assert calls == ["ip", "powershell"], "`ip` is still tried first"
    assert [i.name for i in interfaces] == ["Wi-Fi"], "loopback is filtered as it is on Linux"
    assert interfaces[0].ip == "192.168.1.106"
    assert interfaces[0].subnet == "192.168.1.0/24"


def test_a_single_powershell_address_is_parsed_as_well_as_a_list() -> None:
    """ConvertTo-Json emits a bare object when there is exactly one address."""
    single = tools._parse_powershell_interfaces(
        '{"InterfaceAlias":"Ethernet","IPAddress":"10.20.0.1","PrefixLength":22}'
    )

    assert [i.name for i in single] == ["Ethernet"]
    assert single[0].subnet == "10.20.0.0/22"


@pytest.mark.parametrize(
    "stdout",
    ["", "not json", "[]", '[{"InterfaceAlias":"X"}]', '[{"IPAddress":"nope","PrefixLength":24}]'],
)
def test_unusable_powershell_output_yields_no_interfaces(stdout: str) -> None:
    assert tools._parse_powershell_interfaces(stdout) == []


async def test_own_device_hosts_are_interface_ips_plus_loopback() -> None:
    interfaces = [
        InterfaceInfo(name="wlan0", ip="192.168.1.106", prefix=24, subnet="192.168.1.0/24"),
        InterfaceInfo(name="lan22", ip="10.20.0.1", prefix=22, subnet="10.20.0.0/22"),
    ]

    hosts = await tools.own_device_hosts(interfaces)

    assert hosts == ["10.20.0.1", "127.0.0.1", "192.168.1.106"]


async def test_own_device_hosts_always_include_loopback_even_without_interfaces() -> None:
    hosts = await tools.own_device_hosts([])

    assert hosts == ["127.0.0.1"]


async def test_probe_web_hosts_returns_only_hosts_with_open_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_probe_one_host(host: str) -> Any:
        if host == "10.0.0.5":
            return WebHost(
                host=host, ports=[80, 443], urls=["http://10.0.0.5", "https://10.0.0.5"]
            )
        return WebHost(host=host, ports=[], urls=[])

    monkeypatch.setattr(tools, "_probe_one_host", fake_probe_one_host)

    web_hosts = await tools.probe_web_hosts(["10.0.0.5", "10.0.0.9"])

    assert [w.host for w in web_hosts] == ["10.0.0.5"]
    assert web_hosts[0].urls == ["http://10.0.0.5", "https://10.0.0.5"]


async def test_scan_services_parses_nmap_xml_into_service_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1700000000">
  <host><status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.2" extrainfo="protocol 2.0"/></port>
      <port protocol="tcp" portid="8081"><state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="53"><state state="filtered"/><service name="domain"/></port>
    </ports>
  </host>
</nmaprun>"""

    async def fake_run_command(command: list[str], **_: Any) -> tuple[int, str, str]:
        assert command[0] == "nmap"
        assert "127.0.0.1" in command and "10.0.0.10" in command
        return 0, fake_nmap_xml, ""

    monkeypatch.setattr(tools, "run_command", fake_run_command)

    services = await tools.scan_services(["10.0.0.10", "127.0.0.1"])

    assert len(services) == 2
    assert services[0].host == "10.0.0.10"
    assert services[0].port == 22
    assert services[0].service == "ssh"
    assert services[0].product == "OpenSSH"
    assert services[0].version == "7.2"
    # Filtered ports are dropped, only open ones survive.
    assert [s.port for s in services] == [22, 8081]


async def test_scan_services_returns_empty_when_nmap_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_command(command: list[str], **_: Any) -> tuple[int, str, str]:
        return 1, "", "nmap: not found"

    monkeypatch.setattr(tools, "run_command", fake_run_command)

    assert await tools.scan_services(["10.0.0.10"]) == []


async def test_scan_services_noop_without_hosts() -> None:
    assert await tools.scan_services([]) == []


async def test_run_discovery_scans_own_device_and_reports_notes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_list_interfaces() -> Any:
        return [
            InterfaceInfo(name="eth0", ip="10.0.0.10", prefix=24, subnet="10.0.0.0/24")
        ]

    async def fake_own_device_hosts(interfaces: Any) -> Any:
        return ["10.0.0.10", "127.0.0.1"]

    async def fake_web_hosts(hosts: list[str]) -> Any:
        return [
            WebHost(host=h, ports=[8081], urls=[f"http://{h}:8081"])
            for h in hosts
        ]

    async def fake_scan_services(hosts: list[str]) -> Any:
        return [
            ServicePort(host=h, port=22, service="ssh", product="OpenSSH", version="7.2")
            for h in hosts
        ]

    monkeypatch.setattr(tools, "list_interfaces", fake_list_interfaces)
    monkeypatch.setattr(tools, "own_device_hosts", fake_own_device_hosts)
    monkeypatch.setattr(tools, "probe_web_hosts", fake_web_hosts)
    monkeypatch.setattr(tools, "scan_services", fake_scan_services)

    interfaces, subnets, live_hosts, web_hosts, services, notes = await tools.run_discovery()

    assert interfaces[0].ip == "10.0.0.10"
    assert subnets == ["10.0.0.0/24"]
    # The current device's own addresses are the scan targets - no sweep.
    assert live_hosts == ["10.0.0.10", "127.0.0.1"]
    assert [w.host for w in web_hosts] == ["10.0.0.10", "127.0.0.1"]
    assert [s.host for s in services] == ["10.0.0.10", "127.0.0.1"]
    assert any("no subnet sweep" in n for n in notes)


# ---------------------------------------------------------------------------
# The endpoint: overlapping callers share one scan.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_scan_in_flight() -> Any:
    """Clear the module-level in-flight task so these tests do not leak into each other."""
    discovery_endpoint._in_flight = None
    yield
    discovery_endpoint._in_flight = None


async def _stub_run_discovery(monkeypatch: pytest.MonkeyPatch, *, delay: float) -> list[int]:
    """Replace the discovery stage with a slow no-op, and count how often it runs."""
    runs: list[int] = []

    async def fake_run_discovery() -> Any:
        runs.append(1)
        await asyncio.sleep(delay)
        return [], [], ["127.0.0.1"], [], [], ["stubbed"]

    monkeypatch.setattr(discovery_endpoint, "run_discovery", fake_run_discovery)
    return runs


async def test_overlapping_requests_share_one_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two callers, one nmap.

    React's development double-render mounts the Services page twice, so every
    visit fired two `POST /discovery/run` within a few hundred milliseconds and
    the log showed `discovery.run.start` twice. Each is a full `nmap -sV` pass
    over the same addresses, and they slow each other down.
    """
    runs = await _stub_run_discovery(monkeypatch, delay=0.05)

    first, second = await asyncio.gather(
        discovery_endpoint.run(), discovery_endpoint.run()
    )

    assert len(runs) == 1, "the second caller must join the first scan, not start another"
    assert first is second, "both callers get the same report"
    assert first.live_hosts == ["127.0.0.1"]


async def test_a_later_request_starts_a_fresh_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Coalescing must not turn into caching - Re-scan has to actually re-scan."""
    runs = await _stub_run_discovery(monkeypatch, delay=0)

    await discovery_endpoint.run()
    await discovery_endpoint.run()

    assert len(runs) == 2


async def test_one_caller_giving_up_does_not_cancel_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client hanging up must not abort the scan someone else is waiting on."""
    runs = await _stub_run_discovery(monkeypatch, delay=0.1)

    impatient = asyncio.create_task(discovery_endpoint.run())
    patient = asyncio.create_task(discovery_endpoint.run())
    await asyncio.sleep(0.01)
    impatient.cancel()

    report = await patient

    assert len(runs) == 1
    assert report.live_hosts == ["127.0.0.1"]


async def test_a_failed_scan_is_not_remembered(monkeypatch: pytest.MonkeyPatch) -> None:
    """A crashed scan must not wedge every later request onto the same failure."""

    async def failing() -> Any:
        raise RuntimeError("nmap exploded")

    monkeypatch.setattr(discovery_endpoint, "run_discovery", failing)
    with pytest.raises(RuntimeError):
        await discovery_endpoint.run()

    runs = await _stub_run_discovery(monkeypatch, delay=0)
    report = await discovery_endpoint.run()

    assert len(runs) == 1
    assert report.live_hosts == ["127.0.0.1"]
