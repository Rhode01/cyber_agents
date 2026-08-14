"""Scan scope, read from the backend.

The allowlist that governs scanning comes from two places, and they answer
different questions:

* **Config** (``SCAN_ALLOWED_TARGETS``) - what is true of this deployment.
  Loopback, the private network the stack runs on. It must keep working when the
  backend is down, so it is never fetched.
* **The backend** (``GET /scan-scope/networks``) - what an operator authorised for
  a client, from the UI. It changes without a redeploy, which is the whole point.

The two are unioned. Neither can override the other, so nothing an operator adds
can remove the deployment's own ranges, and nothing in config can silently
authorise a client host.

**A failed fetch narrows scope, never widens it.** If the backend is unreachable
the config list stands alone: a scan of a client host is refused until the backend
is back, rather than being permitted on the strength of a list we could not read.
That is the wrong-in-the-safe-direction choice - a refusal is visible and
recoverable, an unauthorised scan is neither.

There is no cache. A scan takes minutes and one HTTP call takes milliseconds, so
caching would buy nothing measurable and would cost the property that matters
most: a revoked authorisation stops working the moment it is revoked.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.tools.targets import Network, parse_networks

logger = logging.getLogger("app")

SCOPE_NETWORKS_PATH = "/scan-scope/networks"


async def fetch_scope_networks(
    client: httpx.AsyncClient, *, request_timeout: float
) -> list[Network]:
    """Fetch the operator-managed scope, or an empty list if it cannot be read."""
    try:
        response = await client.get(SCOPE_NETWORKS_PATH, timeout=request_timeout)
    except httpx.HTTPError as exc:
        logger.warning(
            "scope.fetch.unreachable error=%s "
            "(falling back to the configured allowlist only)",
            exc,
        )
        return []

    if response.is_error:
        logger.warning(
            "scope.fetch.error status=%s (falling back to the configured allowlist only)",
            response.status_code,
        )
        return []

    try:
        body: Any = response.json()
    except ValueError:
        logger.warning("scope.fetch.malformed (falling back to the configured allowlist only)")
        return []

    raw = body.get("networks") if isinstance(body, dict) else None
    if not isinstance(raw, list):
        logger.warning("scope.fetch.malformed (falling back to the configured allowlist only)")
        return []

    # parse_networks drops anything unreadable, which narrows rather than widens.
    return parse_networks([str(entry) for entry in raw])
