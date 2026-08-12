"""Validation for URLs an operator submits for analysis.

This is the *operator input* boundary: it rejects a submission that is obviously
not something we should go and look at, so the analyst gets a 422 with a reason
instead of a message that fails deep inside a worker.

**It is not the SSRF control.** The check that matters happens in the ai.engine
immediately before a request is made, per redirect hop, against the resolved
address - see ``app.agents.phishing.fetch``. The two guard different things and
neither replaces the other:

* this one runs once, on a string, before anything is stored;
* that one runs on every hop, on resolved IPs, and is what stops a public
  hostname that resolves to 169.254.169.254 from being fetched.

A hostname is deliberately **not** resolved here. Resolution belongs next to the
connection it protects - resolving now and connecting later is a rebinding window
by construction, and it would also make an API call's latency depend on DNS.
"""

from __future__ import annotations

import ipaddress
from typing import Final
from urllib.parse import urlsplit

ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
MAX_URL_LENGTH: Final = 2048

# Hostnames that name the local machine or a local network without needing DNS.
_LOCAL_HOSTNAMES: Final[frozenset[str]] = frozenset({"localhost", "localhost.localdomain"})
_LOCAL_SUFFIXES: Final[tuple[str, ...]] = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".home.arpa",
)


class InvalidSubmittedUrlError(ValueError):
    """The submitted URL is not something we will analyse."""


def _is_local_literal(host: str) -> bool:
    """Is ``host`` an IP literal pointing somewhere we must not fetch?"""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def validate_submitted_url(raw: str) -> str:
    """Normalise and check a URL an analyst asked us to inspect.

    Args:
        raw: The submitted string.

    Returns:
        The URL, trimmed. Case is preserved - the path and query of a phishing
        URL are frequently case-significant tokens, and lowercasing the whole
        thing would change what gets fetched.

    Raises:
        InvalidSubmittedUrlError: empty, too long, wrong scheme, no host, has
            credentials, or names a local/private address outright.
    """
    candidate = (raw or "").strip()
    if not candidate:
        msg = "a URL is required"
        raise InvalidSubmittedUrlError(msg)
    if len(candidate) > MAX_URL_LENGTH:
        msg = f"URLs are limited to {MAX_URL_LENGTH} characters"
        raise InvalidSubmittedUrlError(msg)
    if any(char in candidate for char in "\r\n\t"):
        # Header-injection shaped input. Never valid in a URL, and refusing it
        # here keeps it out of the stored row and the logs.
        msg = "the URL contains control characters"
        raise InvalidSubmittedUrlError(msg)

    try:
        parts = urlsplit(candidate)
    except ValueError as err:
        msg = f"could not parse the URL: {err}"
        raise InvalidSubmittedUrlError(msg) from err

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        listed = ", ".join(sorted(ALLOWED_SCHEMES))
        msg = f"only {listed} URLs can be analysed, not {scheme or 'a relative URL'}"
        raise InvalidSubmittedUrlError(msg)

    try:
        host = parts.hostname
    except ValueError as err:
        msg = f"the URL has an unusable host: {err}"
        raise InvalidSubmittedUrlError(msg) from err
    if not host:
        msg = "the URL has no host"
        raise InvalidSubmittedUrlError(msg)

    if parts.username or parts.password:
        # `https://paypal.com@evil.tld/` is a phishing technique in its own right,
        # and we will not carry credentials into an outbound request either way.
        # Rejected rather than stripped: silently changing what an analyst asked
        # us to look at is worse than telling them.
        msg = "the URL contains embedded credentials; submit it without the user info part"
        raise InvalidSubmittedUrlError(msg)

    lowered = host.lower()
    if lowered in _LOCAL_HOSTNAMES or lowered.endswith(_LOCAL_SUFFIXES):
        msg = f"{host} names this machine or a local network, which cannot be a phishing host"
        raise InvalidSubmittedUrlError(msg)
    if _is_local_literal(lowered):
        msg = f"{host} is a loopback, private, or reserved address and will not be fetched"
        raise InvalidSubmittedUrlError(msg)

    return candidate
