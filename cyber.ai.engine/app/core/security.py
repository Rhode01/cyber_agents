"""The internal-key boundary for inbound requests.

Only service-to-service routes are guarded: the agent routers and discovery. They
launch scans and spend model budget, so they are not safe to serve to anyone who
can reach the port.

``/health`` stays open. The container healthcheck has no key, and the backend's
``/system/modules`` page probes it to show whether this service is up.

The posture is fail-closed, decided in ``Settings``: outside ``APP_ENV=local`` the
service refuses to start without a key, and locally a key is optional but turns
enforcement on as soon as it is set - so the production path can be exercised
before it is deployed.
"""

from __future__ import annotations

from typing import Annotated

from cyber_contracts import INTERNAL_KEY_HEADER, matches_internal_key
from fastapi import Depends, Header, HTTPException, status

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


async def require_internal_key(
    x_internal_key: Annotated[str | None, Header(alias=INTERNAL_KEY_HEADER)] = None,
) -> None:
    """Reject a request that does not carry the configured internal key."""
    settings = get_settings()
    if not settings.enforce_internal_key:
        logger.debug("auth.disabled", reason="no internal key configured and APP_ENV is local")
        return

    if matches_internal_key(x_internal_key, settings.internal_key):
        return

    logger.warning("auth.rejected", presented=bool(x_internal_key))
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"A valid {INTERNAL_KEY_HEADER} header is required.",
    )


InternalKeyGuard = Depends(require_internal_key)
"""Router-level dependency. Applied to whole routers, not individual routes."""
