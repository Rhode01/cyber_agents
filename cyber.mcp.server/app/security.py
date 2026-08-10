"""The internal-key boundary for this service.

**This mirrors ``cyber_contracts/security.py`` on purpose.** Every other module
gets those two definitions from the shared contract package, but this one is
built from its own directory as its build context (see the note at the top of
the Dockerfile) and deliberately has no path dependencies. Copying one header
name and one comparison is a smaller price than making this module's image
depend on the whole repository tree. **If the contract changes, change this too.**

Why the MCP endpoint needs a key at all: ``nmap_service_scan`` runs a scanner and
``run_agent`` launches pipeline work. Published on a port with no authentication,
that is a remote scan-and-execute primitive for anyone who can reach it.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Awaitable, Callable
from typing import Final

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("app")

INTERNAL_KEY_HEADER: Final = "X-Internal-Key"

# The container healthcheck has no key to present, and locking it out would make
# the service look permanently unhealthy to Docker.
OPEN_PATHS: Final = frozenset({"/health"})


def matches_internal_key(presented: str | None, expected: str) -> bool:
    """Is ``presented`` the configured internal key? Constant-time."""
    if not expected or not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


class InternalKeyMiddleware:
    """Require the internal key on everything except the open paths.

    ``enforce=False`` is the local-development posture: the check is skipped and
    every request is logged as unauthenticated, so "I forgot to set the key" is
    noisy rather than silent. Production refuses to start without one - see the
    validator in ``app.config``.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        expected_key: str,
        enforce: bool,
    ) -> None:
        self.app = app
        self._expected_key = expected_key
        self._enforce = enforce
        self._warned = False

    async def __call__(self, scope: dict, receive: object, send: object) -> None:  # type: ignore[type-arg]
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        if request.url.path in OPEN_PATHS or not self._enforce:
            if not self._enforce and not self._warned:
                self._warned = True
                logger.warning(
                    "mcp.auth.disabled path=%s - INTERNAL_KEY is unset and APP_ENV is local; "
                    "every caller is accepted",
                    request.url.path,
                )
            await self.app(scope, receive, send)
            return

        if matches_internal_key(request.headers.get(INTERNAL_KEY_HEADER), self._expected_key):
            await self.app(scope, receive, send)
            return

        logger.warning("mcp.auth.rejected path=%s", request.url.path)
        response: Response = JSONResponse(
            {"detail": f"A valid {INTERNAL_KEY_HEADER} header is required."},
            status_code=401,
        )
        await response(scope, receive, send)  # type: ignore[arg-type]
