"""Artifact ingestion.

Parsing lives in the backend, not the ai.engine: the backend owns the raw
artifact and the normalized form it produces is what crosses the wire. The
ai.engine reasons over ``NormalizedScan`` / ``NormalizedMessage`` and never sees
the original bytes.

Two families, kept apart on purpose. Scanner output is sniffed by
``detect_format`` and parsed by ``parse``; email is sniffed by
``detect_message_format`` and parsed by ``parse_email_mime``. Overloading one
registry would mean an ``.eml`` posted to ``/scans`` half-worked, where two means
it gets a clean 415 pointing somewhere else.
"""

from app.services.ingestion.email import parse_email_mime
from app.services.ingestion.errors import ScanParseError, UnsupportedScanFormatError
from app.services.ingestion.messages import detect_message_format
from app.services.ingestion.nmap import parse_nmap_xml
from app.services.ingestion.registry import detect_format, parse

__all__ = [
    "ScanParseError",
    "UnsupportedScanFormatError",
    "detect_format",
    "detect_message_format",
    "parse",
    "parse_email_mime",
    "parse_nmap_xml",
]
