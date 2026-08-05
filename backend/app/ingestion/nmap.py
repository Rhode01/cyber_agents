"""Nmap XML parser.

Three properties matter more than completeness:

1. **The input is hostile.** It arrives from an upload form and describes
   machines that may be compromised. ``defusedxml`` is used rather than the
   stdlib parser so entity expansion (billion laughs) and external entity
   references (XXE) raise instead of exhausting memory or reading local files.
   Every collection is bounded.

2. **Nothing is sanitised.** Service banners, product strings, versions and
   hostnames are carried through byte for byte. Stripping suspicious content
   here would destroy the evidence the injection detector needs, and would imply
   a safety that does not exist - a caller would then reasonably assume the
   output is safe to interpolate anywhere. Fencing happens exactly once, at the
   prompt boundary, in the ai.engine.

3. **Only ``open`` ports survive.** Closed and filtered ports are noise for
   vulnerability assessment, and dropping them early keeps the candidate count
   (and therefore the prompt) proportional to real exposure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

# Imported for the element type only. Parsing goes through defusedxml below.
from xml.etree.ElementTree import Element

from cyberagents_contracts import NormalizedScan, ScanFormat, ScanHost, ScanPort
from defusedxml.ElementTree import ParseError as DefusedParseError
from defusedxml.ElementTree import fromstring

from app.ingestion.errors import ScanParseError

MAX_HOSTS: Final = 4096
MAX_PORTS_PER_HOST: Final = 512
MAX_HOSTNAMES_PER_HOST: Final = 16
MAX_CPE_PER_PORT: Final = 8

# Field caps mirror the contract's max_length so a long banner is truncated here
# rather than failing validation after the whole file has been parsed.
_SERVICE_MAX: Final = 64
_PRODUCT_MAX: Final = 256
_VERSION_MAX: Final = 128
_EXTRAINFO_MAX: Final = 256
_SCANNER_MAX: Final = 64
_ADDRESS_MAX: Final = 64


def _clip(value: str | None, limit: int) -> str | None:
    """Truncate an untrusted string to its contract length, preserving content."""
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return stripped[:limit]


def _parse_started_at(raw: str | None) -> datetime | None:
    """Nmap's ``start`` attribute is a Unix timestamp. Absent or junk means None."""
    if not raw:
        return None
    try:
        return datetime.fromtimestamp(int(raw), tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_port(element: Element) -> ScanPort | None:
    """Build one ScanPort, or None when the port is not open or is unusable."""
    state_element = element.find("state")
    state = (state_element.get("state") or "") if state_element is not None else ""
    if state != "open":
        return None

    raw_portid = element.get("portid")
    if raw_portid is None:
        return None
    try:
        port_number = int(raw_portid)
    except ValueError:
        return None
    if not 1 <= port_number <= 65535:
        return None

    service_element = element.find("service")
    service = product = version = extrainfo = None
    cpe: list[str] = []
    if service_element is not None:
        service = _clip(service_element.get("name"), _SERVICE_MAX)
        product = _clip(service_element.get("product"), _PRODUCT_MAX)
        version = _clip(service_element.get("version"), _VERSION_MAX)
        extrainfo = _clip(service_element.get("extrainfo"), _EXTRAINFO_MAX)
        for cpe_element in service_element.findall("cpe")[:MAX_CPE_PER_PORT]:
            value = _clip(cpe_element.text, _PRODUCT_MAX)
            if value:
                cpe.append(value)

    return ScanPort(
        port=port_number,
        protocol=_clip(element.get("protocol"), 8) or "tcp",
        state=state,
        service=service,
        product=product,
        version=version,
        extrainfo=extrainfo,
        cpe=cpe,
    )


def _parse_host(element: Element) -> ScanHost | None:
    """Build one ScanHost, or None when it has no usable address."""
    address = None
    for address_element in element.findall("address"):
        addrtype = address_element.get("addrtype")
        if addrtype in {"ipv4", "ipv6"}:
            address = _clip(address_element.get("addr"), _ADDRESS_MAX)
            if address:
                break
    if address is None:
        return None

    status_element = element.find("status")
    status = (status_element.get("state") or "unknown") if status_element is not None else "unknown"

    hostnames: list[str] = []
    hostnames_element = element.find("hostnames")
    if hostnames_element is not None:
        for hostname_element in hostnames_element.findall("hostname")[:MAX_HOSTNAMES_PER_HOST]:
            name = _clip(hostname_element.get("name"), _ADDRESS_MAX)
            if name and name not in hostnames:
                hostnames.append(name)

    ports: list[ScanPort] = []
    ports_element = element.find("ports")
    if ports_element is not None:
        port_elements = ports_element.findall("port")
        if len(port_elements) > MAX_PORTS_PER_HOST:
            msg = (
                f"host {address} declares {len(port_elements)} ports, "
                f"above the {MAX_PORTS_PER_HOST} limit"
            )
            raise ScanParseError(msg)
        for port_element in port_elements:
            port = _parse_port(port_element)
            if port is not None:
                ports.append(port)

    return ScanHost(address=address, hostnames=hostnames, status=status, ports=ports)


def parse_nmap_xml(content: str) -> NormalizedScan:
    """Parse Nmap XML output into the shared normalized shape.

    Raises:
        ScanParseError: malformed XML, a non-Nmap document, or a bound exceeded.
    """
    if not content.strip():
        msg = "the uploaded file is empty"
        raise ScanParseError(msg)

    try:
        root = fromstring(content)
    except DefusedParseError as err:
        msg = f"not well-formed XML: {err}"
        raise ScanParseError(msg) from err
    except Exception as err:
        # defusedxml raises EntityDeclared / DTDForbidden / ExternalReferenceForbidden
        # for the attacks it blocks. Catching broadly here is deliberate: any
        # refusal from the hardened parser is a parse failure to the caller.
        msg = f"the XML was rejected as unsafe to parse: {type(err).__name__}: {err}"
        raise ScanParseError(msg) from err

    if root.tag != "nmaprun":
        msg = f"expected an Nmap report with a <nmaprun> root, found <{root.tag}>"
        raise ScanParseError(msg)

    host_elements = root.findall("host")
    if len(host_elements) > MAX_HOSTS:
        msg = f"scan declares {len(host_elements)} hosts, above the {MAX_HOSTS} limit"
        raise ScanParseError(msg)

    hosts: list[ScanHost] = []
    for host_element in host_elements:
        host = _parse_host(host_element)
        if host is not None:
            hosts.append(host)

    return NormalizedScan(
        format=ScanFormat.nmap_xml,
        scanner=_clip(root.get("scanner"), _SCANNER_MAX) or "nmap",
        scanner_version=_clip(root.get("version"), _SCANNER_MAX),
        started_at=_parse_started_at(root.get("start")),
        hosts=hosts,
    )
