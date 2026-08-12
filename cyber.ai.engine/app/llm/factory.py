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

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI

from app.core.config import get_settings
from app.core.logging import get_logger

# Re-exported, not defined here. The canonical definition moved to app.llm.errors so
# it can carry a status code and a hint like every other assessment failure; this
# alias keeps the agents that import it from this module working unchanged.
from app.llm.errors import LlmNotConfiguredError

logger = get_logger(__name__)

__all__ = [
    "LlmNotConfiguredError",
    "describe_model",
    "extract_message_text",
    "get_chat_model",
    "require_configured_chat_model",
    "reset_chat_model_cache",
    "resolve_provider",
]


def extract_message_text(response: BaseMessage) -> str:
    """Flatten a chat response to a single plain-text string.

    OpenAI returns ``str`` content; Anthropic returns a list of content blocks
    that may include ``thinking`` blocks from reasoning models. Joining only the
    text blocks keeps downstream JSON parsing looking at one string either way.
    """
    content = response.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


@lru_cache(maxsize=4)
def get_chat_model(
    provider: str,
    api_key: str,
    model_name: str,
    base_url: str | None = None,
    temperature: float = 0.0,
    max_retries: int = 2,
    timeout: float = 60.0
) -> BaseChatModel:
    """Return the shared chat model, constructing it on first use."""
    if provider == "anthropic":
        logger.info(
            "llm.constructed",
            provider="anthropic",
            model=model_name,
            base_url=base_url or "anthropic-default",
        )
        return ChatAnthropic(
            model=model_name,
            api_key=api_key or "not-configured",
            anthropic_api_url=base_url if base_url else None,
            temperature=temperature,
            max_retries=max_retries,
            default_request_timeout=timeout,
            # The SDK's non-streaming path fails on servers that answer every
            # request with SSE regardless of the Accept header.
            streaming=True,
        )
    
    # Fallback to OpenAI
    logger.info(
        "llm.constructed",
        provider="openai",
        model=model_name,
        base_url=base_url or "openai-default",
    )
    return ChatOpenAI(
        model=model_name,
        api_key=api_key or "not-configured",
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries,
    )


def resolve_provider(context: dict[str, str] | None = None) -> str:
    """Which provider a call with this context would actually use.

    Extracted so ``describe_model`` and ``require_configured_chat_model`` cannot
    disagree. They used to: the former hardcoded "openai", so /health reported the
    wrong provider whenever Anthropic was selected, and the pre-flight error named
    the wrong environment variable.
    """
    return (context or {}).get("llm_provider", "openai")


def require_configured_chat_model(context: dict[str, str] | None = None) -> BaseChatModel:
    """Return the chat model, refusing if no credentials are present.

    Refusing here is a **pre-flight** check: it happens before any prompt is built,
    so a misconfigured deployment fails on the first request instead of after a
    60-second timeout.
    """
    settings = get_settings()
    ctx = context or {}

    provider = resolve_provider(ctx)
    api_key = ctx.get("llm_api_key") or ctx.get("openai_api_key") or settings.openai_api_key
    model_name = ctx.get("llm_model") or settings.openai_model
    base_url = ctx.get("llm_base_url") or settings.resolved_base_url

    if not api_key:
        # Name the variable that is actually missing for the provider in play, not
        # a generic "the key". An operator reading this should not have to work out
        # which of two keys the deployment wanted.
        variable = "ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY"
        msg = f"{variable} is not set, so the ai.engine cannot call the {provider} model"
        raise LlmNotConfiguredError(msg)


    return get_chat_model(
        provider=provider,
        api_key=api_key,
        model_name=model_name,
        base_url=base_url,
        temperature=settings.openai_temperature,
        max_retries=settings.openai_max_retries,
        timeout=settings.openai_timeout_seconds
    )


def describe_model(context: dict[str, str] | None = None) -> dict[str, Any]:
    """Report the resolved LLM configuration without exposing the key.

    Takes the same ``context`` as ``require_configured_chat_model`` and resolves the
    provider through the same helper, so /health cannot claim one provider while a
    request would use another.
    """
    settings = get_settings()
    provider = resolve_provider(context)
    if provider == "openai" and settings.resolved_base_url is not None:
        provider = "openai-compatible"
    return {
        "provider": provider,
        "model": settings.openai_model,
        "base_url": settings.resolved_base_url,
        "temperature": settings.openai_temperature,
        "configured": settings.llm_is_configured,
    }


def reset_chat_model_cache() -> None:
    """Drop the cached model. Used by tests that vary the environment."""
    get_chat_model.cache_clear()
