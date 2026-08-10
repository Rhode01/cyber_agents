"""The internal-key contract for service-to-service calls.

The three services never import one another, so the header name and the
comparison have to live in the one place all of them already depend on. A
hardcoded string repeated in three repos drifts; this does not.

**Scope: this authenticates a service, not a user.** A valid key means "this
request came from inside the platform" and nothing more - any holder of the key
can call any service-to-service route. Per-user authentication and RBAC are a
separate concern and still deferred; see the ``require_principal`` stub in
``cyber.backend/app/core/security.py``.
"""

from __future__ import annotations

import hmac
from typing import Final

INTERNAL_KEY_HEADER: Final = "X-Internal-Key"
"""Header carrying the shared internal key on service-to-service requests."""


def matches_internal_key(presented: str | None, expected: str) -> bool:
    """Is ``presented`` the configured internal key?

    Compared with :func:`hmac.compare_digest` so the time taken does not reveal
    how many leading characters were correct.

    An empty ``expected`` never matches. A service that forgot to configure a
    key must not silently accept every caller through a blank-equals-blank
    accident, so "unconfigured" is a decision each service makes explicitly at
    its own boundary rather than something this function grants by default.
    """
    if not expected or not presented:
        return False
    # Encoded rather than compared as str: compare_digest rejects non-ASCII
    # str inputs, and a header value is whatever the caller sent.
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
