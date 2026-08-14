"""MCP server.

Exposes two kinds of capability to MCP clients:

* **Platform reads and triggers** - thin proxies over the backend REST API, for an
  external MCP host (Claude Desktop and similar) to inspect findings and launch
  agent runs.
* **Security tools** - nmap, CVE enrichment and exposure classification, called by
  the ai.engine's agents. Tool *execution* lives here rather than in the agents so
  there is one place that runs a scanner, one target allowlist, and one audit
  point.

Everything under ``/mcp`` requires the internal key. ``/health`` does not, because
the container healthcheck has no key to present.
"""

from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from app import __version__
from app.config import get_settings
from app.security import INTERNAL_KEY_HEADER, InternalKeyMiddleware
from app.tools import (
    MAX_SWEEP_ADDRESSES,
    CveLookup,
    check_range,
    check_target,
    classify_exposure,
    duration_seconds,
    fetch_page,
    fetch_scope_networks,
    lookup_dns_records,
    parse_networks,
    run_command,
    tool_result,
)
from app.tools.rdap import lookup_domain_age as rdap_lookup_domain_age
from app.tools.targets import Network

logger = logging.getLogger("app")

settings = get_settings()

MCP_ENDPOINT = "/mcp"

# The backend mounts its routers at the root - there is no /api/v1 prefix. See
# cyber.backend/app/main.py and the path set asserted in its test_health.py.
BACKEND_FINDINGS = "/findings"
BACKEND_AGENTS = "/agents"

# The backend caps this itself; clamping here turns a 422 into a served page.
MAX_FINDINGS_LIMIT = 200

AGENT_NAMES = ("vulnerability", "phishing", "network", "webapp")

mcp = MCPServer(settings.mcp_server_name)

# Initialised in the lifespan; module-level so the tool functions can reach them.
http_client: httpx.AsyncClient | None = None
cve_lookup: CveLookup | None = None
_scan_networks = parse_networks(settings.scan_allowed_targets)


def get_client() -> httpx.AsyncClient:
    """Return the global HTTP client."""
    if http_client is None:
        raise RuntimeError("HTTP client is not initialized")
    return http_client


def get_cve_lookup() -> CveLookup:
    """Return the global CVE lookup."""
    if cve_lookup is None:
        raise RuntimeError("CVE lookup is not initialized")
    return cve_lookup


async def _allowed_networks() -> list[Network]:
    """Everything this server may scan: the static config plus operator-managed scope.

    Fetched per scan rather than cached. A scan takes minutes and this call takes
    milliseconds, so a cache would buy nothing and would cost the property that
    matters: a revoked authorisation stops working when it is revoked, not when a
    TTL happens to expire.

    A backend that cannot be reached contributes nothing, leaving the configured
    list standing alone - so an outage refuses scans of client hosts rather than
    permitting them on the strength of a list nobody could read. An HTTP client
    that does not exist yet is the same situation and gets the same answer, rather
    than raising: a scan tool that throws where it should refuse turns a policy
    decision into a stack trace.
    """
    if http_client is None:
        logger.warning(
            "scope.fetch.no_client (falling back to the configured allowlist only)"
        )
        return list(_scan_networks)

    fetched = await fetch_scope_networks(
        http_client, request_timeout=settings.backend_timeout_seconds
    )
    return [*_scan_networks, *fetched]


# ---------------------------------------------------------------------------
# Platform reads and triggers
# ---------------------------------------------------------------------------

@mcp.tool()
async def describe_platform() -> dict[str, Any]:
    """Describe this platform: which detection agents exist and what tools exist."""
    return {
        "platform": "Cybersecurity Agents Platform",
        "version": __version__,
        "phase": 2,
        "agents": list(AGENT_NAMES),
        "security_tools": [
            "nmap_service_scan",
            "nmap_host_discovery",
            "nmap_sweep_scan",
            "lookup_cve",
            "lookup_asset_exposure",
        ],
        "note": (
            "Findings are produced by a deterministic rule engine in the ai.engine; "
            "the tools here supply evidence and enrichment, never findings."
        ),
    }


@mcp.tool()
async def list_findings(
    agent: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List findings from the platform backend.

    Args:
        agent: Restrict to one agent: 'vulnerability', 'phishing', 'network', 'webapp'.
        severity: Restrict to one severity: 'critical', 'high', 'medium', 'low', 'info'.
        limit: How many findings to return, newest first. Capped at 200.
    """
    params: dict[str, str | int] = {"limit": max(1, min(limit, MAX_FINDINGS_LIMIT))}
    if agent:
        params["agent"] = agent
    if severity:
        params["severity"] = severity
    return await _backend_get(BACKEND_FINDINGS, params=params)


@mcp.tool()
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Retrieve a single finding by its UUID."""
    return await _backend_get(f"{BACKEND_FINDINGS}/{finding_id}")


@mcp.tool()
async def summarize_findings(asset: str) -> dict[str, Any]:
    """Summarize active findings for one asset (IP, hostname, image name).

    Args:
        asset: The exact asset string recorded on the findings.
    """
    # The backend does this server-side with a grouped query, and reports whether
    # it truncated. Tallying a page of results here would silently under-count.
    return await _backend_get(f"{BACKEND_FINDINGS}/summary", params={"asset": asset})


@mcp.tool()
async def run_agent(
    agent: str,
    source: str,
    raw_input: str = "",
    asset: str | None = None,
    background: bool = False,
) -> dict[str, Any]:
    """Send an artifact to a detection agent for analysis.

    Args:
        agent: 'vulnerability', 'phishing', 'network', or 'webapp'.
        source: The tool that produced the input, e.g. 'nmap', 'openvas', 'trivy', 'zap'.
        raw_input: Raw scanner output. Leave empty to have the agent scan `asset` itself.
        asset: Optional IP or hostname target.
        background: If true, the backend queues the run and returns a job id.
    """
    if agent not in AGENT_NAMES:
        return {
            "error": f"Unknown agent {agent!r}. Expected one of: {', '.join(AGENT_NAMES)}.",
            "status_code": 400,
        }

    client = get_client()
    payload = {
        "source": source,
        "raw_input": raw_input,
        "asset": asset,
        "background": background,
    }
    try:
        response = await client.post(f"{BACKEND_AGENTS}/{agent}/run", json=payload)
    except httpx.HTTPError as exc:
        return {"error": f"The backend could not be reached: {exc}", "status_code": None}
    if response.is_error:
        return {"error": response.text, "status_code": response.status_code}
    return _as_dict(response)


# ---------------------------------------------------------------------------
# Security tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def nmap_service_scan(
    target: str, ports: str | None = None, include_closed: bool = False
) -> dict[str, Any]:
    """Run an Nmap service-version scan and return its raw XML.

    Only targets inside this server's configured scan allowlist are accepted;
    anything else is refused without running the scanner. A hostname is resolved
    first and every address it returns must be in the allowlist, so naming a host
    can never reach somewhere an address could not. The XML is returned verbatim
    for the caller to parse - every string in it is untrusted data.

    Args:
        target: A hostname, or an IP address inside the allowlist, or an
               explicitly local name.
        ports: Optional Nmap port specification, e.g. '22,80,443' or '1-1024'.
               Defaults to Nmap's fast top-100 sweep.
        include_closed: Report closed ports as well as open ones. Off by default,
               because a discovery scan only cares what is listening. Turn it ON to
               *verify* a fix: with Nmap's --open, a host whose scanned ports are all
               closed is omitted from the XML entirely, which is indistinguishable
               from a scan that failed. The closed-port record is the only evidence
               that a port was examined and found shut.
    """
    decision = await check_target(
        target, await _allowed_networks(), resolve=settings.scan_resolve_hostnames
    )
    if not decision.allowed:
        return tool_result(
            ok=False,
            tool="nmap",
            error=decision.reason,
            meta={
                "target": decision.target,
                "requested": decision.requested or target,
                "addresses": list(decision.addresses),
                "refused": True,
            },
        )

    # Configurable rather than a bare "nmap": the Windows installer does not put it
    # on the machine PATH, so relying on the ambient environment reported "nmap is
    # not installed" on a host where it plainly was.
    command = [settings.scan_nmap_path, "-Pn", "-sV", "-oX", "-"]
    if not include_closed:
        command.insert(3, "--open")
    # Sized for a remote host: without a host timeout a firewalled target burns the
    # whole budget and our own kill discards the XML, so a slow scan reports nothing
    # rather than what it did manage to see.
    command += [
        f"-{settings.scan_timing_template}",
        "--host-timeout",
        f"{settings.scan_host_timeout_seconds:g}s",
    ]
    if decision.is_ipv6:
        command.append("-6")
    if ports:
        cleaned = _clean_port_spec(ports)
        if cleaned is None:
            return tool_result(
                ok=False,
                tool="nmap",
                error=(
                    f"{ports!r} is not a valid port specification. Use digits, commas "
                    "and hyphens, e.g. '22,80,8000-8100'."
                ),
                meta={"target": decision.target, "refused": True},
            )
        command += ["-p", cleaned]
    else:
        command.append("-F")
    command.append(decision.target)

    started_at = time.monotonic()
    returncode, stdout, stderr = await run_command(
        command, timeout_seconds=settings.scan_timeout_seconds, label="nmap"
    )
    elapsed = duration_seconds(started_at)
    logger.info(
        "mcp.nmap target=%s requested=%s returncode=%s duration=%s bytes=%s",
        decision.target,
        decision.requested or target,
        returncode,
        elapsed,
        len(stdout),
    )
    return tool_result(
        ok=returncode == 0 and bool(stdout.strip()),
        tool="nmap",
        output=stdout,
        error=stderr.strip(),
        meta={
            "target": decision.target,
            # What the caller asked for, and everything it resolved to. A finding is
            # keyed by the address that was scanned, so this is the only record of
            # the name behind it.
            "requested": decision.requested or target,
            "addresses": list(decision.addresses),
            "returncode": returncode,
            "duration_seconds": elapsed,
            "format": "nmap_xml",
        },
    )


@mcp.tool()
async def nmap_host_discovery(target_range: str) -> dict[str, Any]:
    """Find which addresses in a range are alive, without probing their services.

    The cheap half of a network sweep: a ping sweep over the whole range, so the
    expensive half is proportional to the hosts that actually exist rather than to
    the size of the range. A /24 is seconds; service-scanning all 256 addresses
    blindly would be most of an hour spent on addresses nobody is using.

    The entire range must be inside an authorised scope entry. A range that is only
    partly authorised is refused outright, because a sweep would reach hosts nobody
    attested to.

    Args:
        target_range: A CIDR range, e.g. '192.168.1.0/24'. A single address works too.
    """
    decision = check_range(target_range, await _allowed_networks())
    if not decision.allowed:
        return tool_result(
            ok=False,
            tool="nmap-discovery",
            error=decision.reason,
            meta={"range": decision.network, "refused": True},
        )

    command = [
        settings.scan_nmap_path,
        "-sn",  # host discovery only: no port scan, no version probing
        "-n",   # no reverse DNS - it doubles the wall clock and nothing here reads it
        f"-{settings.scan_timing_template}",
        "-oX",
        "-",
        decision.network,
    ]

    started_at = time.monotonic()
    returncode, stdout, stderr = await run_command(
        command, timeout_seconds=settings.scan_discovery_timeout_seconds, label="nmap-discovery"
    )
    elapsed = duration_seconds(started_at)
    hosts = _live_hosts(stdout)
    logger.info(
        "mcp.nmap_discovery range=%s returncode=%s duration=%s live=%s scanned=%s",
        decision.network,
        returncode,
        elapsed,
        len(hosts),
        decision.address_count,
    )
    return tool_result(
        ok=returncode == 0,
        tool="nmap-discovery",
        output=stdout,
        error=stderr.strip(),
        meta={
            "range": decision.network,
            "live_hosts": hosts,
            "live_count": len(hosts),
            "addresses_in_range": decision.address_count,
            "returncode": returncode,
            "duration_seconds": elapsed,
            "format": "nmap_xml",
        },
    )


@mcp.tool()
async def nmap_sweep_scan(hosts: list[str], ports: str | None = None) -> dict[str, Any]:
    """Service-scan several hosts in one pass and return the combined XML.

    The expensive half of a network sweep, run against the addresses host discovery
    found alive. One nmap invocation rather than one per host: nmap parallelises
    across targets far better than we would by issuing them serially.

    **Every host is re-checked against scope here**, not just the range they came
    from. The list arrives as an argument, so trusting it because a previous call
    validated a range would let a doctored intermediate result widen the scan.

    Args:
        hosts: Addresses to scan, as returned by nmap_host_discovery.
        ports: Optional Nmap port specification. Defaults to Nmap's fast sweep.
    """
    if not hosts:
        return tool_result(
            ok=False,
            tool="nmap-sweep",
            error="No hosts were supplied. Run nmap_host_discovery first.",
            meta={"refused": True},
        )
    if len(hosts) > MAX_SWEEP_ADDRESSES:
        return tool_result(
            ok=False,
            tool="nmap-sweep",
            error=(
                f"{len(hosts)} hosts were supplied and one sweep may cover at most "
                f"{MAX_SWEEP_ADDRESSES:,}."
            ),
            meta={"refused": True},
        )

    allowed = await _allowed_networks()
    vetted: list[str] = []
    refused: list[str] = []
    for host in hosts:
        decision = await check_target(host, allowed, resolve=False)
        if decision.allowed:
            vetted.append(decision.target)
        else:
            refused.append(host)

    if not vetted:
        return tool_result(
            ok=False,
            tool="nmap-sweep",
            error=(
                "None of the supplied hosts are inside an authorised range. "
                f"Refused: {', '.join(refused[:10])}"
            ),
            meta={"refused": True, "refused_hosts": refused},
        )

    command = [settings.scan_nmap_path, "-Pn", "-sV", "--open", "-oX", "-"]
    command += [
        f"-{settings.scan_timing_template}",
        "--host-timeout",
        f"{settings.scan_host_timeout_seconds:g}s",
    ]
    if ports:
        cleaned = _clean_port_spec(ports)
        if cleaned is None:
            return tool_result(
                ok=False,
                tool="nmap-sweep",
                error=(
                    f"{ports!r} is not a valid port specification. Use digits, commas "
                    "and hyphens, e.g. '22,80,8000-8100'."
                ),
                meta={"refused": True},
            )
        command += ["-p", cleaned]
    else:
        command.append("-F")
    command += vetted

    started_at = time.monotonic()
    returncode, stdout, stderr = await run_command(
        command, timeout_seconds=settings.scan_sweep_timeout_seconds, label="nmap-sweep"
    )
    elapsed = duration_seconds(started_at)
    logger.info(
        "mcp.nmap_sweep hosts=%s refused=%s returncode=%s duration=%s bytes=%s",
        len(vetted),
        len(refused),
        returncode,
        elapsed,
        len(stdout),
    )
    return tool_result(
        ok=returncode == 0 and bool(stdout.strip()),
        tool="nmap-sweep",
        output=stdout,
        error=stderr.strip(),
        meta={
            "hosts_scanned": vetted,
            # Reported rather than silently dropped: a sweep that covered 40 of 50
            # hosts must not read as a clean bill of health for the other 10.
            "hosts_refused": refused,
            "returncode": returncode,
            "duration_seconds": elapsed,
            "format": "nmap_xml",
        },
    )


def _live_hosts(raw_xml: str) -> list[str]:
    """Addresses reported ``up`` by a ``-sn`` discovery scan.

    Parsed here rather than in the caller so the ai.engine receives a list it can
    act on, not XML it has to understand twice. Unreadable output yields an empty
    list, which the caller sees as "nothing alive" alongside a non-zero returncode.
    """
    try:
        root = ET.fromstring(raw_xml)  # noqa: S314 - local, trusted format layer
    except ET.ParseError:
        return []

    live: list[str] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        address_el = host_el.find("address[@addrtype='ipv4']")
        if address_el is None:
            address_el = host_el.find("address[@addrtype='ipv6']")
        address = address_el.get("addr", "") if address_el is not None else ""
        if address:
            live.append(address)
    return live


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up published details for one CVE identifier.

    Enrichment only: this adds a score, a summary and an exploit signal to a
    finding that already exists. It never establishes that a CVE applies to an
    asset - that comes from the version-range rules in the ai.engine.

    Args:
        cve_id: A CVE identifier, e.g. 'CVE-2021-44228'.
    """
    return await get_cve_lookup().lookup(cve_id)


@mcp.tool()
async def lookup_asset_exposure(asset: str) -> dict[str, Any]:
    """Classify how exposed an asset is, and report what is already known about it.

    Returns 'internal', 'internet' or 'unknown'. A hostname is resolved to decide
    this; one that does not resolve comes back 'unknown' rather than being
    optimistically called internal.

    Args:
        asset: An IP address or hostname.
    """
    classification = await classify_exposure(asset)
    known = await _backend_get(f"{BACKEND_FINDINGS}/summary", params={"asset": asset})
    if "error" in known:
        classification["known_findings"] = {"available": False, "detail": known["error"]}
        return classification

    classification["known_findings"] = {
        "available": True,
        "count": known.get("count"),
        "severities": known.get("severities"),
    }
    return classification


# ---------------------------------------------------------------------------
# Phishing enrichment
#
# These three exist so the ai.engine holds no egress at all. It already holds no
# database; routing DNS, RDAP and the link fetch through here keeps the network
# boundary in one service, next to the target policy that governs it.
# ---------------------------------------------------------------------------

@mcp.tool()
async def dns_records(domain: str) -> dict[str, Any]:
    """Return the SPF, DMARC, DKIM and MX records a domain publishes.

    Answers one question the message itself cannot: an 'spf=pass' header is text the
    delivery path wrote, and a domain that publishes no SPF record cannot have produced
    a pass. Finding no records is a successful lookup with empty lists, not a failure.

    Args:
        domain: A registrable domain, e.g. 'paypal.com'.
    """
    return await lookup_dns_records(domain)


@mcp.tool()
async def lookup_domain_age(domain: str) -> dict[str, Any]:
    """Return how many days ago a domain was registered, over RDAP.

    Phishing infrastructure is usually days old, because domains get reported and burned.
    Not conclusive on its own - a rebrand or a campaign site is legitimately new.

    Args:
        domain: A registrable domain, e.g. 'paypal-secure.example'.
    """
    return await rdap_lookup_domain_age(domain)


@mcp.tool()
async def fetch_url(url: str) -> dict[str, Any]:
    """Follow a suspect link and report what the destination page is.

    **This is the only tool that contacts a host chosen by an attacker**, so it is gated on
    PHISHING_FETCH_ENABLED as well as the per-request opt-in the analyst sets. Redirects are
    followed one hop at a time and every hop is re-checked against the public-only address
    policy, which is what stops a public-looking link from reaching a private service or the
    cloud metadata endpoint.

    Nothing is rendered or executed. The result carries the final host, the redirect chain,
    the page title, whether a password field exists, and where any form submits - the
    login-page signal, established structurally.

    Args:
        url: An absolute http or https URL taken from a message.
    """
    settings = get_settings()
    if not settings.phishing_fetch_enabled:
        return {
            "ok": False,
            "tool": "fetch_url",
            "url": url,
            "error": (
                "Link fetching is disabled on this MCP server. Set PHISHING_FETCH_ENABLED=1 "
                "to allow it. Both this switch and the per-request opt-in must agree before "
                "any request leaves the host."
            ),
            "final_host": "",
            "redirect_chain": [],
            "password_field": False,
        }

    outcome = await fetch_page(url)
    return outcome.as_dict()


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def _clean_port_spec(ports: str) -> str | None:
    """Validate a port specification before it reaches the command line.

    The argv list already prevents shell injection; this stops a malformed spec
    from becoming an nmap flag (a leading '-' would be read as one).
    """
    cleaned = ports.strip().replace(" ", "")
    if not cleaned or len(cleaned) > 256:
        return None
    if not all(char.isdigit() or char in ",-" for char in cleaned):
        return None
    if cleaned[0] in ",-" or cleaned[-1] in ",-":
        return None
    return cleaned


def _as_dict(response: httpx.Response) -> dict[str, Any]:
    """Decode a backend response, keeping non-object bodies readable."""
    try:
        decoded = response.json()
    except ValueError:
        return {"error": "The backend returned a body that is not JSON.", "status_code": None}
    if not isinstance(decoded, dict):
        return {"items": decoded} if isinstance(decoded, list) else {"value": decoded}
    return decoded


async def _backend_get(path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET one backend path, returning errors as data rather than raising."""
    client = get_client()
    try:
        response = await client.get(path, params=params)
    except httpx.HTTPError as exc:
        logger.warning("mcp.backend.unreachable path=%s error=%s", path, exc)
        return {"error": f"The backend could not be reached: {exc}", "status_code": None}
    if response.is_error:
        return {"error": response.text, "status_code": response.status_code}
    return _as_dict(response)


mcp_app = mcp.streamable_http_app(
    transport_security=TransportSecuritySettings(
        allowed_hosts=settings.resolved_allowed_hosts,
        allowed_origins=settings.resolved_allowed_origins,
    )
)


async def health(request: Request) -> JSONResponse:
    """Liveness for the container healthcheck. Deliberately unauthenticated."""
    del request
    return JSONResponse(
        {
            "status": "ok",
            "service": "app",
            "version": __version__,
            "server_name": settings.mcp_server_name,
            "transport": "streamable-http",
            "mcp_endpoint": MCP_ENDPOINT,
            "auth_enforced": settings.enforce_internal_key,
        }
    )


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    """Run the MCP session manager and HTTP client for the lifetime of the ASGI app."""
    del app
    global http_client, cve_lookup
    logging.basicConfig(level=getattr(logging, settings.log_level), format="%(message)s")
    logger.info(
        "app starting: name=%s port=%s auth=%s scan_networks=%s",
        settings.mcp_server_name,
        settings.mcp_port,
        settings.enforce_internal_key,
        len(_scan_networks),
    )

    headers = {"accept": "application/json"}
    if settings.internal_key:
        headers[INTERNAL_KEY_HEADER] = settings.internal_key

    http_client = httpx.AsyncClient(
        base_url=settings.backend_url,
        timeout=settings.backend_timeout_seconds,
        headers=headers,
    )
    # Its own client: the backend client carries the internal key as a default
    # header, and that must never be sent to a third-party CVE service.
    cve_client = httpx.AsyncClient(timeout=settings.cve_lookup_timeout_seconds)
    cve_lookup = CveLookup(
        cve_client,
        base_url=settings.cve_lookup_url,
        timeout_seconds=settings.cve_lookup_timeout_seconds,
        ttl_seconds=settings.cve_cache_ttl_seconds,
        request_interval_seconds=settings.cve_request_interval_seconds,
    )

    async with mcp.session_manager.run(), http_client, cve_client:
        yield

    logger.info("app stopped")


app = Starlette(
    routes=[
        Route("/health", endpoint=health, methods=["GET"]),
        Mount("/", app=mcp_app),
    ],
    middleware=[
        Middleware(
            InternalKeyMiddleware,
            expected_key=settings.internal_key,
            enforce=settings.enforce_internal_key,
        )
    ],
    lifespan=lifespan,
)


def main() -> None:
    """Run over stdio, for an MCP host that launches this as a subprocess."""
    logging.basicConfig(level=getattr(logging, settings.log_level), format="%(message)s")
    logger.info("app starting on stdio: name=%s", settings.mcp_server_name)
    mcp.run()


if __name__ == "__main__":
    main()
