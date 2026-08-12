"""HTTP client for the ai.engine service.

The ai.engine holds no database, so this is the only direction findings travel
during a synchronous run: backend asks, ai.engine answers, backend persists.

Phase 1: the transport and error mapping are real; the ai.engine's answer is a
placeholder.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

import httpx
from cyber_contracts import (
    INTERNAL_KEY_HEADER,
    AgentKind,
    DiscoveryReport,
    FindingBatch,
    PhishingAnalyzeRequest,
    VerificationReport,
    VerificationRequest,
    VulnerabilityAnalyzeRequest,
)

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.schemas.agents import AgentRunRequest

logger = get_logger(__name__)


class AiEngineError(RuntimeError):
    """The ai.engine was unreachable or answered with something unusable."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


MAX_REASON_CHARS = 600
"""Enough to carry a detail and a hint; bounded so an HTML error page cannot fill the
`error` column or the log line."""


def _reason_from(response: httpx.Response) -> str:
    """Pull the operator-facing reason out of an ai.engine error response.

    Its exception handlers answer with ``{"error", "detail", "hint"}`` - the detail says
    what happened and the hint says what to do about it. FastAPI's own validation and
    HTTPException responses use ``detail`` alone, so both shapes are handled.

    Returns "" when the body is not JSON or carries nothing useful, so the caller falls
    back to the status code rather than reporting a slice of an HTML error page.
    """
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""

    detail = body.get("detail")
    if isinstance(detail, list):
        # FastAPI validation errors: a list of {loc, msg, type}.
        detail = "; ".join(
            str(item.get("msg")) for item in detail if isinstance(item, dict) and item.get("msg")
        )
    parts = [str(part).strip() for part in (detail, body.get("hint")) if part]
    return " ".join(parts)[:MAX_REASON_CHARS]


class AiEngineClient:
    """Thin async wrapper over the ai.engine's agent routers."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        headers = {"accept": "application/json"}
        # The ai.engine's agent routes launch scans and spend model budget, so they
        # require the shared internal key. Sent as a default header rather than
        # per-call so a new method cannot forget it.
        if self._settings.internal_key:
            headers[INTERNAL_KEY_HEADER] = self._settings.internal_key

        self._client = httpx.AsyncClient(
            base_url=self._settings.ai_engine_url,
            timeout=httpx.Timeout(self._settings.ai_engine_timeout_seconds),
            headers=headers,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def health(self) -> dict[str, Any]:
        """Return the ai.engine's own health payload."""
        payload = await self._request("GET", "/health")
        return payload

    async def analyze(self, agent: AgentKind, request: AgentRunRequest) -> FindingBatch:
        """Ask one agent to analyse one raw artifact and return its findings.

        The three stub agents still take raw text. The vulnerability agent takes a
        parsed scan instead - see ``analyze_vulnerability``.
        """
        body = {
            "source": request.source,
            "asset": request.asset,
            "raw_input": request.raw_input,
            "context": request.context,
        }
        payload = await self._request("POST", f"/agents/{agent.value}/analyze", json=body)
        return self._as_batch(payload, f"/agents/{agent.value}/analyze")

    async def run_discovery(self) -> DiscoveryReport:
        """Ask the ai.engine to discover interfaces, live hosts, and web hosts.

        The report is proxied to the frontend so the Run page can hand the
        discovered web hosts to the web-app agents as scan targets.
        """
        payload = await self._request("POST", "/discovery/run", json={})
        try:
            return DiscoveryReport.model_validate(payload)
        except ValueError as err:  # pydantic ValidationError subclasses ValueError
            msg = (
                "ai.engine /discovery/run returned a payload that breaks the "
                f"Discovery contract: {err}"
            )
            raise AiEngineError(msg) from err

    async def assess_vulnerability(self, request: VulnerabilityAnalyzeRequest) -> FindingBatch:
        """Send a parsed scan to the vulnerability agent.

        The backend does the parsing, so what crosses the wire is the normalized
        scan rather than the raw XML. Every string inside it is untrusted; the
        ai.engine fences it before it reaches a prompt.

        This posts to ``/assess``, not ``/analyze``. ``/analyze`` takes the generic
        ``AnalyzeRequest``, which forbids extra fields - so sending a parsed scan
        there returned 422 for every uploaded scan until ``/assess`` existed.
        """
        path = "/agents/vulnerability/assess"
        payload = await self._request("POST", path, json=request.model_dump(mode="json"))
        return self._as_batch(payload, path)

    async def assess_phishing(self, request: PhishingAnalyzeRequest) -> FindingBatch:
        """Send a parsed message to the phishing agent.

        Same split as ``assess_vulnerability``: the backend parses the artifact and
        the normalized message crosses the wire, so ``/assess`` rather than
        ``/analyze``. Almost every string inside ``request.message`` is untrusted -
        a phishing email is written to manipulate whoever reads it - and the
        ai.engine fences it before it reaches a prompt.
        """
        path = "/agents/phishing/assess"
        payload = await self._request("POST", path, json=request.model_dump(mode="json"))
        return self._as_batch(payload, path)

    async def verify_vulnerability(self, request: VerificationRequest) -> VerificationReport:
        """Ask the vulnerability agent to re-check hosts and ports.

        Returns coverage as well as observations, because "not detected" is not
        "fixed" - it is also what an unreachable host looks like. The backend
        resolves a finding only when the report proves its port was covered.
        """
        path = "/agents/vulnerability/verify"
        payload = await self._request("POST", path, json=request.model_dump(mode="json"))
        try:
            return VerificationReport.model_validate(payload)
        except ValueError as err:  # pydantic ValidationError subclasses ValueError
            msg = (
                f"ai.engine {path} returned a payload that breaks the Verification "
                f"contract: {err}"
            )
            raise AiEngineError(msg) from err

    @staticmethod
    def _as_batch(payload: dict[str, Any], path: str) -> FindingBatch:
        """Validate a response against the shared contract."""
        try:
            return FindingBatch.model_validate(payload)
        except ValueError as err:  # pydantic ValidationError subclasses ValueError
            msg = f"ai.engine {path} returned a payload that breaks the Finding contract: {err}"
            raise AiEngineError(msg) from err

    async def _request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            response = await self._client.request(method, path, json=json)
            response.raise_for_status()
        except httpx.HTTPStatusError as err:
            reason = _reason_from(err.response)
            logger.warning(
                "ai_engine.http_error",
                method=method,
                path=path,
                status_code=err.response.status_code,
                reason=reason,
            )
            # The reason is carried, not just the status code. The ai.engine answers a
            # failed assessment with {"error", "detail", "hint"} naming what an operator
            # has to fix - a missing OPENAI_API_KEY, a rate limit, a refusal. Reporting
            # only "failed with 503" threw that away and left the UI showing a number,
            # which defeats the point of failing loudly at all.
            msg = f"ai.engine {method} {path} failed with {err.response.status_code}"
            if reason:
                msg = f"{msg}: {reason}"
            raise AiEngineError(msg, status_code=err.response.status_code) from err
        except httpx.HTTPError as err:
            logger.warning("ai_engine.unreachable", method=method, path=path, error=str(err))
            msg = f"ai.engine {method} {path} is unreachable: {err}"
            raise AiEngineError(msg) from err

        decoded: Any = response.json()
        if not isinstance(decoded, dict):
            msg = f"ai.engine {method} {path} returned {type(decoded).__name__}, expected an object"
            raise AiEngineError(msg)
        return decoded
