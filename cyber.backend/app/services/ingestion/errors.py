"""Ingestion failures.

These are *expected* outcomes of accepting a file from a user, not bugs. The
intake job catches them and writes the message onto the scan record, so an
operator sees why their upload did not produce findings.
"""

from __future__ import annotations


class ScanParseError(ValueError):
    """The uploaded artifact could not be parsed into a NormalizedScan."""


class UnsupportedScanFormatError(ScanParseError):
    """The format was recognised but there is no parser for it yet."""
