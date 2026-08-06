"""Target classification helpers shared across agents.

The agents self-launch scans against analyst-supplied targets. Some detections
are meaningless for local hosts: a loopback/private target can never be a
phishing impersonation, and flagging "default logins" on a local instance is
noise. These helpers decide whether a target counts as local so nodes and tools
can skip those checks.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_LOCAL_HOSTNAMES = ("localhost",)
_LOCAL_SUFFIXES = (".localhost", ".local", ".localdomain", ".internal")


def _host_of(target: str) -> str:
    """Extract the bare host (no scheme, port, or path) from a target string."""
    raw = (target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or parsed.netloc or raw
    return host.strip("[]")


def is_local_target(target: str) -> bool:
    """Return True when ``target`` points at the loopback or a local/private host.

    Hostnames are matched syntactically (``localhost``, ``*.local``,
    ``*.internal``); IP literals are classified with ``ipaddress`` (loopback,
    RFC 1918 private, link-local). No DNS resolution is performed, so this is
    deterministic and side-effect free.
    """
    host = _host_of(target).lower()
    if not host:
        return False

    if host in _LOCAL_HOSTNAMES or any(host.endswith(s) for s in _LOCAL_SUFFIXES):
        return True

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False

    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )
