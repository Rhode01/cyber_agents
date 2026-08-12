"""Turning assessment failures into HTTP responses.

Registered once in ``create_app``, so every agent that raises an ``AssessmentError``
gets the same shape without a try/except in its router. A node raises the domain
error it means; the status code and the operator-facing hint travel with the
exception class rather than being re-decided at each call site.

The body is deliberately three fields:

* ``error`` - the class name, so a caller can branch without parsing prose;
* ``detail`` - what happened, safe to show an analyst;
* ``hint`` - what to do about it, aimed at whoever runs the deployment.

The backend renders ``detail`` verbatim onto the intake row, which is what makes the
"fail loudly" decision visible: a missing API key becomes text in the UI rather than
a plausible-looking result nobody should trust.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger
from app.llm.errors import AssessmentError

logger = get_logger(__name__)


async def _assessment_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Render an ``AssessmentError`` with the status its class declares."""
    # FastAPI types handlers as taking Exception; the registration below guarantees
    # what actually arrives, and narrowing here keeps mypy honest without a cast.
    if not isinstance(exc, AssessmentError):  # pragma: no cover - registration guarantees it
        raise exc

    logger.warning(
        "http.assessment_error",
        path=request.url.path,
        error=type(exc).__name__,
        status_code=exc.status_code,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": type(exc).__name__, "detail": str(exc), "hint": exc.hint},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach the assessment-error handler to ``app``.

    One registration on the base class covers every subclass, so a new error type
    needs no wiring here - it only needs a ``status_code`` and a ``hint``.
    """
    app.add_exception_handler(AssessmentError, _assessment_error_handler)
