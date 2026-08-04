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
from cyberagents_contracts import AgentKind, FindingBatch

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.schemas.agents import AgentRunRequest

logger = get_logger(__name__)


class AiEngineError(RuntimeError):
    """The ai.engine was unreachable or answered with something unusable."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AiEngineClient:
    """Thin async wrapper over the ai.engine's agent routers."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._client = httpx.AsyncClient(
            base_url=self._settings.ai_engine_url,
            timeout=httpx.Timeout(self._settings.ai_engine_timeout_seconds),
            headers={"accept": "application/json"},
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
        """Ask one agent to analyse one artifact and return its findings."""
        body = {
            "source": request.source,
            "asset": request.asset,
            "raw_input": request.raw_input,
            "context": request.context,
        }
        payload = await self._request("POST", f"/agents/{agent.value}/analyze", json=body)
        try:
            return FindingBatch.model_validate(payload)
        except ValueError as err:  # pydantic ValidationError subclasses ValueError
            msg = f"ai.engine returned a payload that does not match the Finding contract: {err}"
            raise AiEngineError(msg) from err

    async def _request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            response = await self._client.request(method, path, json=json)
            response.raise_for_status()
        except httpx.HTTPStatusError as err:
            logger.warning(
                "ai_engine.http_error",
                method=method,
                path=path,
                status_code=err.response.status_code,
            )
            msg = f"ai.engine {method} {path} failed with {err.response.status_code}"
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
