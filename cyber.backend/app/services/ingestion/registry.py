"""Format detection and parser dispatch.

One place maps a ``ScanFormat`` to a parser, so adding OpenVAS later is a single
entry rather than a new branch at every call site.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from cyberagents_contracts import NormalizedScan, ScanFormat

from app.ingestion.errors import ScanParseError, UnsupportedScanFormatError
from app.ingestion.nmap import parse_nmap_xml

# Root elements that identify a format without parsing the whole document.
_ROOT_MARKERS: Final[tuple[tuple[str, ScanFormat], ...]] = (
    ("<nmaprun", ScanFormat.nmap_xml),
    ("<get_reports_response", ScanFormat.openvas_xml),
    ("<report", ScanFormat.openvas_xml),
)

_SNIFF_CHARS: Final = 8192

PARSERS: Final[dict[ScanFormat, Callable[[str], NormalizedScan]]] = {
    ScanFormat.nmap_xml: parse_nmap_xml,
    # TODO(phase-3): OpenVAS. detect_format already recognises it so an upload
    # gets a clear 415 rather than a confusing parse error.
}


def detect_format(content: str) -> ScanFormat:
    """Identify a scanner format by sniffing the opening element.

    Raises:
        ScanParseError: nothing recognisable in the first few KB.
    """
    head = content[:_SNIFF_CHARS].lower()
    for marker, scan_format in _ROOT_MARKERS:
        if marker in head:
            return scan_format

    msg = "could not identify the scanner format; expected Nmap XML"
    raise ScanParseError(msg)


def parse(content: str, scan_format: ScanFormat) -> NormalizedScan:
    """Parse content with the parser registered for ``scan_format``.

    Raises:
        UnsupportedScanFormatError: recognised format, no parser yet.
        ScanParseError: the content did not parse.
    """
    parser = PARSERS.get(scan_format)
    if parser is None:
        msg = f"{scan_format.value} is recognised but not supported yet"
        raise UnsupportedScanFormatError(msg)
    return parser(content)
