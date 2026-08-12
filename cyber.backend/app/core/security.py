"""Authentication.

Two different things live here, and conflating them would be a mistake:

* ``require_principal`` answers "which *user* is this?" and is still a
  placeholder. Everyone is an anonymous analyst. The seam is in the right place so
  a later phase can swap the body for OIDC without touching routes. Real user
  auth, RBAC and audit logging are deferred.

* ``require_internal_key`` answers "did this come from inside the platform?" and
  is real. It guards the routes the ai.engine calls back on to write findings -
  routes no browser touches. It authenticates a service, not a person, and grants
  nothing about *which* user's data may be read.

The browser-facing routes remain unauthenticated, which is a known gap tracked
against ``require_principal``, not something the internal key addresses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from cyber_contracts import INTERNAL_KEY_HEADER, matches_internal_key
from fastapi import Depends, Header, HTTPException, status

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Principal:
    """Whoever is making the request."""

    subject: str
    roles: frozenset[str]

    def has_role(self, role: str) -> bool:
        return role in self.roles


ANONYMOUS_ANALYST = Principal(subject="anonymous", roles=frozenset({"analyst"}))


async def require_principal(
    x_request_subject: Annotated[str | None, Header()] = None,
) -> Principal:
    """Resolve the caller.

    Phase 1 stub: everyone is an analyst. The optional header only exists so
    request logs can be correlated during development - it grants nothing and
    must never be trusted once real auth lands.
    """
    if x_request_subject:
        return Principal(subject=x_request_subject, roles=frozenset({"analyst"}))
    return ANONYMOUS_ANALYST


CurrentPrincipal = Annotated[Principal, Depends(require_principal)]


async def require_internal_key(
    x_internal_key: Annotated[str | None, Header(alias=INTERNAL_KEY_HEADER)] = None,
) -> None:
    """Reject a request that does not carry the configured internal key.

    Applied only to service-to-service routes - the finding writes the ai.engine
    performs. When no key is configured the check is skipped, which is the local
    default; setting one turns enforcement on everywhere at once.
    """
    settings = get_settings()
    if not settings.enforce_internal_key:
        return

    if matches_internal_key(x_internal_key, settings.internal_key):
        return

    logger.warning("auth.internal_key.rejected", presented=bool(x_internal_key))
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"A valid {INTERNAL_KEY_HEADER} header is required.",
    )


InternalKeyGuard = Depends(require_internal_key)
"""Route-level dependency for the service-to-service write paths."""
