"""Scanner output parsers — Track 1, Phase 2.

Each parser accepts raw text (or bytes where appropriate) and returns a
structured representation the agent nodes can reason over.  All parsers are
pure functions: no I/O, no side effects, no database access.

Usage::

    from app.parsers import nmap, trivy, zap, email as email_parser

Parsers raise ``ParseError`` on completely unparseable input so the caller can
decide whether to fall back to raw-text analysis or reject the request early.
"""

from __future__ import annotations


class ParseError(ValueError):
    """Raised when a parser cannot extract anything useful from its input."""
