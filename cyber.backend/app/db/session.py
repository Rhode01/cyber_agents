"""Async engine and session management.

The engine is created lazily so importing the app never opens a socket - that
keeps unit tests and ``alembic --sql`` offline runs free of a live database.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    """Return the process-wide async engine."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.db_echo,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=settings.db_pool_pre_ping,
        future=True,
    )


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide session factory."""
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding one session per request."""
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Close pooled connections on shutdown."""
    if get_engine.cache_info().currsize:
        await get_engine().dispose()
