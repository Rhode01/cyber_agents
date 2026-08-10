"""Scanner output ingestion.

Parsing lives in the backend, not the ai.engine: the backend owns the raw
artifact and the normalized form it produces is what crosses the wire. The
ai.engine reasons over ``NormalizedScan`` and never sees the original bytes.
"""

from app.services.ingestion.errors import ScanParseError, UnsupportedScanFormatError
from app.services.ingestion.nmap import parse_nmap_xml
from app.services.ingestion.registry import detect_format, parse

__all__ = [
    "ScanParseError",
    "UnsupportedScanFormatError",
    "detect_format",
    "parse",
    "parse_nmap_xml",
]
