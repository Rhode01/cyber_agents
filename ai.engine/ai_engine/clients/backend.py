"""HTTP client for the backend.

This is the ai.engine's only route to persistence. In Phase 1 the synchronous
path is the one in use - a router returns findings and the backend stores them -
so this client exists for the long-running case a later phase needs: a graph that
runs for minutes and pushes findings back as it goes.

Stub in Phase 1: the transport is real, nothing calls it yet.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

import httpx
from cyberagents_contracts import FindingBatch

from ai_engine.core.config import Settings, get_settings
from ai_engine.core.logging import get_logger

logger = get_logger(__name__)


class BackendError(RuntimeError):
    """The backend was unreachable or rejected the request."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class BackendClient:
    """Thin async wrapper over the backend's HTTP surface."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._client = httpx.AsyncClient(
            base_url=self._settings.backend_url,
            timeout=httpx.Timeout(self._settings.backend_timeout_seconds),
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
        """Return the backend's health payload."""
        return await self._request("GET", "/health")

    async def push_findings(self, batch: FindingBatch) -> list[dict[str, Any]]:
        """Hand a batch of findings to the backend for persistence.

        TODO(phase-2): called by long-running graphs that cannot return findings
        inside the request that started them.
        """
        response = await self._raw_request(
            "POST", "/findings/batch", json=batch.model_dump(mode="json")
        )
        decoded: Any = response.json()
        if not isinstance(decoded, list):
            msg = "backend POST /findings/batch returned an object, expected a list"
            raise BackendError(msg)
        return [item for item in decoded if isinstance(item, dict)]

    async def _request(self, method: str, path: str) -> dict[str, Any]:
        response = await self._raw_request(method, path)
        decoded: Any = response.json()
        if not isinstance(decoded, dict):
            msg = f"backend {method} {path} returned {type(decoded).__name__}, expected an object"
            raise BackendError(msg)
        return decoded

    async def _raw_request(
        self, method: str, path: str, *, json: Any = None
    ) -> httpx.Response:
        try:
            response = await self._client.request(method, path, json=json)
            response.raise_for_status()
        except httpx.HTTPStatusError as err:
            logger.warning(
                "backend.http_error",
                method=method,
                path=path,
                status_code=err.response.status_code,
            )
            msg = f"backend {method} {path} failed with {err.response.status_code}"
            raise BackendError(msg, status_code=err.response.status_code) from err
        except httpx.HTTPError as err:
            logger.warning("backend.unreachable", method=method, path=path, error=str(err))
            msg = f"backend {method} {path} is unreachable: {err}"
            raise BackendError(msg) from err

        return response
