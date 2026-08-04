"""ChatOpenAI factory.

``langchain-openai``'s ``ChatOpenAI`` is the platform's single LLM interface and
OpenAI's hosted API is the default provider. Model name, optional base URL, and
API key all come from the environment, so pointing every agent at a different
model is a config change and never a code change.

Construction is lazy and cached. Phase 1 builds the client but never invokes it:
no request leaves this process.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from langchain_openai import ChatOpenAI

from ai_engine.core.config import get_settings
from ai_engine.core.logging import get_logger

logger = get_logger(__name__)


class LlmNotConfiguredError(RuntimeError):
    """No API key is present, so a live call could not succeed."""


@lru_cache
def get_chat_model() -> ChatOpenAI:
    """Return the shared chat model, constructing it on first use.

    Constructing without a key is allowed on purpose - it keeps import and
    startup free of credentials. ``require_configured_chat_model`` is the
    accessor to use once a phase actually calls the model.
    """
    settings = get_settings()

    model = ChatOpenAI(
        model=settings.openai_model,
        api_key=settings.openai_api_key or "not-configured",
        base_url=settings.resolved_base_url,
        temperature=settings.openai_temperature,
        timeout=settings.openai_timeout_seconds,
        max_retries=settings.openai_max_retries,
    )

    logger.info(
        "llm.constructed",
        model=settings.openai_model,
        base_url=settings.resolved_base_url or "openai-default",
        configured=settings.llm_is_configured,
    )
    return model


def require_configured_chat_model() -> ChatOpenAI:
    """Return the chat model, refusing if no credentials are present."""
    if not get_settings().llm_is_configured:
        msg = "OPENAI_API_KEY is not set, so the ai.engine cannot call the model"
        raise LlmNotConfiguredError(msg)
    return get_chat_model()


def describe_model() -> dict[str, Any]:
    """Report the resolved LLM configuration without exposing the key."""
    settings = get_settings()
    return {
        "provider": "openai" if settings.resolved_base_url is None else "openai-compatible",
        "model": settings.openai_model,
        "base_url": settings.resolved_base_url,
        "temperature": settings.openai_temperature,
        "configured": settings.llm_is_configured,
    }


def reset_chat_model_cache() -> None:
    """Drop the cached model. Used by tests that vary the environment."""
    get_chat_model.cache_clear()
