"""Placeholder authentication.

Phase 1 deliberately ships no real authentication. This module exists so the
seam is already in the right place: routes depend on ``require_principal``, and
a later phase swaps the body for OIDC or session auth without touching routes.

Real auth, RBAC, and audit logging are deferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header


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
