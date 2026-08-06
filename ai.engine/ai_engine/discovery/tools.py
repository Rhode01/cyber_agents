"""Network discovery for the pipeline.

Discovery is the first stage of a run: it answers "what web service does the
current device expose?" so the web-app agents get real targets.

The stage is deliberately tool-driven and deterministic (no LLM): list the
connected IPv4 interfaces, take the device's own addresses from them (plus
loopback, so local services are reachable), and TCP-probe those addresses for
common web ports. There is no whole-subnet sweep: the machine running the
pipeline is itself the target, so its neighbours are never pinged.

Everything discovered is untrusted data - hosts and service banners can be
anything - and is carried through the pipeline as scan targets, never as
instructions.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time

from cyberagents_contracts import InterfaceInfo, ServicePort, WebHost

from ai_engine.agents.common.scanning import run_command
from ai_engine.core.logging import get_logger
from ai_engine.parsers import ParseError
from ai_engine.parsers.nmap import parse as parse_nmap_xml

logger = get_logger(__name__)

# Common web ports probed on the device. 80/443 get the default scheme; the
# others keep an explicit port so Nuclei targets them correctly. The dev-stack
# ports are included because the MVP runs the platform itself on this machine.
_WEB_PORTS = (80, 443, 3000, 8000, 8003, 8004, 8080, 8081, 8443, 8888)

# Host-route prefixes (/32, /31, /30) and loopback/link-local ranges are not
# worth reporting as subnets; point-to-point links carry no web hosts.
_MAX_PREFIX = 30
_LINK_LOCAL_NET = ipaddress.ip_network("169.254.0.0/16")
_LOOPBACK_NET = ipaddress.ip_network("127.0.0.0/8")

# Cap on how many addresses an interface subnet may hold before it is skipped.
# Nothing here is swept anymore - the cap only keeps huge bridge/VPN ranges out
# of the reported subnet list.
_MAX_SUBNET_ADDRESSES = 1 << 12  # a /20 and smaller (e.g. /21, /22, ... /32)

_PROBE_TIMEOUT_SECONDS = 1.5

# The nmap -sV pass targets the union of the probed web ports and a few common
# infra ports (SSH, mail, PostgreSQL, Redis, …) so "Services Active" lists the
# device's real exposure, not just the web surface. Targets stay limited to the
# device's own addresses.
_SERVICE_SCAN_PORTS = sorted(
    set(_WEB_PORTS)
    | {22, 25, 53, 110, 143, 445, 3306, 5432, 6379, 9000, 9200, 27017}
)
_SERVICE_SCAN_TIMEOUT_SECONDS = 120.0


def _parse_iface_line(line: str) -> InterfaceInfo | None:
    """Turn one ``ip -o -4 addr show`` line into an InterfaceInfo.

    Example line (``ip -o`` separates columns with spaces and tabs):
    ``3: wlan0 inet 192.168.1.106/24 brd 192.168.1.255 scope global dynamic``
    """
    fields = line.split()
    if len(fields) < 4 or fields[2] != "inet":
        return None
    name = fields[1]
    try:
        addr = ipaddress.ip_interface(fields[3])
    except ValueError:
        return None
    return InterfaceInfo(
        name=name,
        ip=str(addr.ip),
        prefix=addr.network.prefixlen,
        subnet=str(addr.network),
    )


async def list_interfaces() -> list[InterfaceInfo]:
    """Enumerate connected non-loopback IPv4 interfaces via ``ip``.

    The ``-o`` flag makes the output one line per address (machine parseable);
    ``-4`` restricts it to IPv4, which is all the MVP's scanners target.
    """
    returncode, stdout, stderr = await run_command(
        ["ip", "-o", "-4", "addr", "show"],
        timeout_seconds=15,
        label="ip",
    )
    if returncode != 0:
        logger.warning("discovery.interfaces.failed", returncode=returncode, error=stderr)
        return []

    interfaces: list[InterfaceInfo] = []
    for line in stdout.splitlines():
        iface = _parse_iface_line(line)
        if iface is None:
            continue
        if iface.name == "lo" or iface.ip.startswith("127."):
            continue
        try:
            net = ipaddress.ip_network(iface.subnet)
        except ValueError:
            continue
        if net.prefixlen > _MAX_PREFIX:
            logger.info("discovery.interfaces.skip", name=iface.name, reason="host-route")
            continue
        if net.overlaps(_LOOPBACK_NET) or net.overlaps(_LINK_LOCAL_NET):
            continue
        if net.num_addresses > _MAX_SUBNET_ADDRESSES:
            logger.info("discovery.interfaces.skip", name=iface.name, reason="subnet-too-large")
            continue
        interfaces.append(iface)

    logger.info("discovery.interfaces", count=len(interfaces))
    return interfaces


async def own_device_hosts(interfaces: list[InterfaceInfo]) -> list[str]:
    """Return the addresses of the current device, from its own interfaces.

    Each connected interface contributes its address; loopback is added so the
    device's local services (e.g. a scanner test target on 127.0.0.1) are part
    of the scan. No neighbours on any subnet are probed.
    """
    return sorted({iface.ip for iface in interfaces} | {"127.0.0.1"})


async def _probe_one_host(host: str) -> WebHost:
    """Probe the common web ports on one address and return what answered."""
    async def _try_port(port: int) -> int | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (OSError, TimeoutError):
            return None

    results = await asyncio.gather(*(_try_port(p) for p in _WEB_PORTS))
    open_ports = sorted(p for p in results if p is not None)
    urls = [_url_for_port(host, port) for port in open_ports]
    return WebHost(host=host, ports=open_ports, urls=urls)


def _url_for_port(host: str, port: int) -> str:
    if port == 80:
        return f"http://{host}"
    if port == 443:
        return f"https://{host}"
    scheme = "https" if port in (8443,) else "http"
    return f"{scheme}://{host}:{port}"


async def probe_web_hosts(hosts: list[str]) -> list[WebHost]:
    """Probe a list of addresses for web services, concurrently."""
    probed = await asyncio.gather(*(_probe_one_host(h) for h in hosts))
    web_hosts = [w for w in probed if w.ports]
    logger.info("discovery.web_hosts", probed=len(hosts), found=len(web_hosts))
    return web_hosts


async def scan_services(live_hosts: list[str]) -> list[ServicePort]:
    """Run a light nmap ``-sV`` pass over the device's own addresses.

    Targets are the current device's addresses only - never a subnet sweep. The
    ``-sV`` version detection is what fills the service/version fields that the
    "Services Active" page renders. When nmap is unavailable or the scan fails
    the stage degrades to an empty list rather than failing the whole report.
    """
    if not live_hosts:
        return []

    returncode, stdout, stderr = await run_command(
        [
            "nmap",
            "-Pn",
            "-sV",
            "-p",
            ",".join(str(p) for p in _SERVICE_SCAN_PORTS),
            "--open",
            "-oX",
            "-",
            *live_hosts,
        ],
        timeout_seconds=_SERVICE_SCAN_TIMEOUT_SECONDS,
        label="nmap-services",
    )
    if returncode != 0:
        logger.warning("discovery.services.failed", returncode=returncode, error=stderr)
        return []

    try:
        hosts = parse_nmap_xml(stdout)
    except ParseError as exc:
        logger.warning("discovery.services.parse_failed", error=str(exc))
        return []

    services: list[ServicePort] = []
    for host in hosts:
        for svc in host.services:
            if svc.state != "open":
                continue
            services.append(
                ServicePort(
                    host=host.ip or "(unknown)",
                    port=svc.port,
                    protocol=svc.protocol,
                    service=svc.service or None,
                    product=svc.product or None,
                    version=svc.version or None,
                    extra_info=svc.extra_info or None,
                )
            )

    logger.info("discovery.services", hosts=len(hosts), found=len(services))
    return services


async def run_discovery() -> (
    tuple[list[InterfaceInfo], list[str], list[str], list[WebHost], list[ServicePort], list[str]]
):
    """Run the full discovery pipeline and return its parts.

    Returns ``(interfaces, subnets, live_hosts, web_hosts, services, notes)`` so
    the router can assemble the report and stamp the duration in one place.
    """
    started_at = time.monotonic()
    notes: list[str] = []

    interfaces = await list_interfaces()
    if not interfaces:
        notes.append("No connected IPv4 interfaces found; nothing to scan.")

    subnets = [iface.subnet for iface in interfaces]

    # Scan the current device itself - the addresses of its own connected
    # interfaces plus loopback - never the whole subnet.
    live_hosts = await own_device_hosts(interfaces)
    notes.append(
        "Discovery scans the current device (its own interface addresses); no subnet sweep."
    )

    web_hosts = await probe_web_hosts(live_hosts) if live_hosts else []
    if not web_hosts:
        notes.append(
            "No web service answered on the device's addresses (127.0.0.1 + interface IPs)."
        )

    services = await scan_services(live_hosts) if live_hosts else []
    if not services:
        notes.append("nmap -sV found no open services on the device's addresses.")

    duration_seconds = round(time.monotonic() - started_at, 2)
    logger.info(
        "discovery.done",
        interfaces=len(interfaces),
        live_hosts=len(live_hosts),
        web_hosts=len(web_hosts),
        services=len(services),
        duration_seconds=duration_seconds,
    )
    return interfaces, subnets, live_hosts, web_hosts, services, notes
