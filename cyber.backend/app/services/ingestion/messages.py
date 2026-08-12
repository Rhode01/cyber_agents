"""Message format detection.

Kept separate from ``registry.py`` on purpose. That module maps ``ScanFormat`` to
a scanner parser and drives ``POST /scans``; overloading it would mean an ``.eml``
posted to the scan endpoint half-worked. Two sniffers means an ``.eml`` sent to
``/scans`` gets a clean 415 pointing somewhere else, which is the useful answer.
"""

from __future__ import annotations

import re
from typing import Final

from cyber_contracts import MessageFormat

from app.services.ingestion.errors import ScanParseError

# Enough to see the header block of any real message without decoding the body.
_SNIFF_BYTES: Final = 8192

# Any one of these at the start of a line makes it a message rather than a
# document that merely contains a colon. `Received` and `From` are the two a
# real message essentially always has; the rest cover exports that dropped the
# delivery path (saved drafts, API exports, forensic extracts).
_HEADER_MARKERS: Final[tuple[bytes, ...]] = (
    b"received:",
    b"from:",
    b"message-id:",
    b"mime-version:",
    b"subject:",
    b"return-path:",
    b"delivered-to:",
    b"authentication-results:",
)

# A header line: field name, optional whitespace, colon. RFC 5322 forbids spaces
# in the name, which is what stops "note: see below" in a text file matching.
_HEADER_LINE_RE: Final = re.compile(rb"^[!-9;-~]+:", re.MULTILINE)


def detect_message_format(raw: bytes) -> MessageFormat:
    """Identify a submitted artifact by sniffing its opening header block.

    Args:
        raw: The submitted bytes.

    Returns:
        Always ``MessageFormat.email_mime``. A URL submission does not come
        through here - it arrives as JSON on its own route, already typed.

    Raises:
        ScanParseError: nothing header-shaped in the first few KB.
    """
    head = raw[:_SNIFF_BYTES]
    lowered = head.lower()

    # `mbox` exports begin with a "From " envelope line that is not a header.
    if lowered.startswith(b"from "):
        return MessageFormat.email_mime

    for line in _HEADER_LINE_RE.finditer(head):
        candidate = head[line.start() : line.end()].lower()
        if candidate in _HEADER_MARKERS:
            return MessageFormat.email_mime

    msg = (
        "could not identify this as an email message; expected RFC 5322 headers "
        "such as From: or Received: near the start of the file"
    )
    raise ScanParseError(msg)
