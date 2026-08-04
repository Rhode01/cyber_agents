"""Shared test fixtures.

The ASGI transport does not run the application lifespan, so importing and
exercising the app in unit tests never opens a database connection.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

RUN_INTEGRATION = os.getenv("RUN_INTEGRATION_TESTS") == "1"

requires_database = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="Set RUN_INTEGRATION_TESTS=1 with PostgreSQL running to exercise this.",
)


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """An HTTP client bound directly to the ASGI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://backend.test") as http_client:
        yield http_client
