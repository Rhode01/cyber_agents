"""Shared route dependencies."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.services.ai_engine.client import AiEngineClient

SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


async def get_ai_engine_client() -> AsyncIterator[AiEngineClient]:
    """Yield an ai.engine client and close its connection pool afterwards."""
    client = AiEngineClient()
    try:
        yield client
    finally:
        await client.aclose()


AiEngineDep = Annotated[AiEngineClient, Depends(get_ai_engine_client)]
