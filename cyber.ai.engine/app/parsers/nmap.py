"""Nmap output parser.

Supports three Nmap output formats:
- XML  (-oX)  — richest; preferred
- Grepable (-oG) — moderate
- Normal (-oN)  — fallback text parsing

Returns a list of ``NmapHost`` dataclasses.

Example::

    hosts = parse(raw_xml)
    for h in hosts:
        for svc in h.services:
            print(h.ip, svc.port, svc.service, svc.version)
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.parsers import ParseError


@dataclass
class NmapService:
    port: int
    protocol: str          # tcp / udp
    state: str             # open / closed / filtered
    service: str           # ssh, http, ftp …
    product: str           # OpenSSH, Apache …
    version: str           # 7.2, 2.4.41 …
    extra_info: str        # any banner/extra info
    cpe: list[str] = field(default_factory=list)


@dataclass
class NmapHost:
    ip: str
    hostname: str
    state: str             # up / down
    os_guess: str          # best OS guess or ""
    services: list[NmapService] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse(raw: str) -> list[NmapHost]:
    """Auto-detect format and return parsed hosts.

    Tries XML first, then grepable, then normal text.
    Raises ``ParseError`` if none produce anything.
    """
    raw = raw.strip()
    if not raw:
        raise ParseError("Empty input")

    if raw.startswith("<?xml") or raw.startswith("<nmaprun"):
        return _parse_xml(raw)

    if raw.startswith("# Nmap") and "Host:" in raw:
        return _parse_grepable(raw)

    hosts = _parse_normal(raw)
    if not hosts:
        raise ParseError("Could not identify Nmap output format")
    return hosts


# ---------------------------------------------------------------------------
# XML (-oX)
# ---------------------------------------------------------------------------

def _parse_xml(raw: str) -> list[NmapHost]:
    try:
        root = ET.fromstring(raw)  # noqa: S314 — local, trusted format layer
    except ET.ParseError as exc:
        raise ParseError(f"Invalid Nmap XML: {exc}") from exc

    hosts: list[NmapHost] = []
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        hn_el = host_el.find(".//hostname[@type='user']") or host_el.find(".//hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""

        # Best OS guess
        os_guess = ""
        osmatch = host_el.find(".//osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name", "")

        services: list[NmapService] = []
        for port_el in host_el.findall(".//port"):
            port_state_el = port_el.find("state")
            port_state = port_state_el.get("state", "") if port_state_el is not None else ""

            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            extra = svc_el.get("extrainfo", "") if svc_el is not None else ""
            cpe_list = [c.text or "" for c in (svc_el.findall("cpe") if svc_el is not None else [])]

            services.append(NmapService(
                port=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state=port_state,
                service=svc_name,
                product=product,
                version=version,
                extra_info=extra,
                cpe=cpe_list,
            ))

        hosts.append(
            NmapHost(ip=ip, hostname=hostname, state=state, os_guess=os_guess, services=services)
        )

    if not hosts:
        raise ParseError("Nmap XML contained no host entries")
    return hosts


# ---------------------------------------------------------------------------
# Grepable (-oG)
# ---------------------------------------------------------------------------

_GREP_HOST_RE = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)", re.MULTILINE)
_GREP_PORT_RE = re.compile(r"(\d+)/(\w+)/(\w+)//([^/]*)/([^/]*)/([^/]*)/")

def _parse_grepable(raw: str) -> list[NmapHost]:
    hosts: list[NmapHost] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        host_m = _GREP_HOST_RE.match(line)
        if not host_m:
            continue
        ip, hostname = host_m.group(1), host_m.group(2)

        services: list[NmapService] = []
        for pm in _GREP_PORT_RE.finditer(line):
            port, proto, state, svc, product, version = pm.groups()
            services.append(NmapService(
                port=int(port), protocol=proto, state=state,
                service=svc, product=product, version=version, extra_info="",
            ))

        hosts.append(NmapHost(ip=ip, hostname=hostname, state="up", os_guess="", services=services))

    return hosts


# ---------------------------------------------------------------------------
# Normal text (-oN) — best-effort
# ---------------------------------------------------------------------------

_NORMAL_HOST_RE = re.compile(r"Nmap scan report for (.+)")
_NORMAL_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|closed|filtered\S*)\s+(\S+)\s*(.*)", re.MULTILINE
)
_VERSION_START_RE = re.compile(r"^\d")


def _split_trailing_parens(text: str) -> tuple[str, str]:
    """Split ``"Apache httpd 2.4.41 ((Ubuntu))"`` into body and parenthesised extra.

    Nmap's normal output puts extra-info in a trailing parenthesised group, which
    may itself contain parentheses. Scanned from the right with a depth counter
    rather than by regex, because ``\\(.*\\)$`` mis-splits ``"((Ubuntu))"``.
    """
    stripped = text.rstrip()
    if not stripped.endswith(")"):
        return stripped, ""

    depth = 0
    for index in range(len(stripped) - 1, -1, -1):
        char = stripped[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return stripped[:index].rstrip(), stripped[index + 1 : -1].strip()
    return stripped, ""


def _split_normal_banner(banner: str) -> tuple[str, str, str]:
    """Split a normal-output service banner into product, version and extra-info.

    Normal output renders the same three fields the XML format carries as
    attributes, just concatenated: ``product version (extrainfo)``. Recovering
    them matters because every version-comparison rule reads ``version``, and a
    parser that leaves it empty turns the whole rule engine into a no-op while
    still looking like it parsed successfully.

    The version is taken to start at the first whitespace-delimited token
    beginning with a digit, and runs to the end - so ``"OpenSSH 7.4p1 Debian
    10+deb9u7"`` yields version ``"7.4p1 Debian 10+deb9u7"``, matching what the
    XML attribute would have held for the same service.
    """
    body, extra_info = _split_trailing_parens(banner.strip())
    if not body:
        return "", "", extra_info

    tokens = body.split()
    for index, token in enumerate(tokens):
        if _VERSION_START_RE.match(token):
            return " ".join(tokens[:index]), " ".join(tokens[index:]), extra_info

    # No numeric token at all: it is all product name, e.g. "Postfix smtpd".
    return body, "", extra_info


def _parse_normal(raw: str) -> list[NmapHost]:
    hosts: list[NmapHost] = []
    blocks = _NORMAL_HOST_RE.split(raw)

    i = 1  # blocks[0] is preamble
    while i < len(blocks):
        host_header = blocks[i].strip()
        block_text = blocks[i + 1] if i + 1 < len(blocks) else ""

        # "host (ip)" or just "ip"
        ip_m = re.search(r"\(?([\d.:a-fA-F]+)\)?$", host_header)
        ip = ip_m.group(1) if ip_m else host_header
        hostname = host_header if ip_m and ip != host_header else ""

        services: list[NmapService] = []
        for pm in _NORMAL_PORT_RE.finditer(block_text):
            port, proto, state, svc, banner = pm.groups()
            product, version, extra_info = _split_normal_banner(banner)
            services.append(NmapService(
                port=int(port), protocol=proto, state=state,
                service=svc, product=product, version=version, extra_info=extra_info,
            ))

        hosts.append(NmapHost(ip=ip, hostname=hostname, state="up", os_guess="", services=services))
        i += 2

    return hosts
