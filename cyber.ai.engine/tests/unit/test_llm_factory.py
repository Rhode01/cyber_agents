"""The LLM factory builds from the environment and makes no live call."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage
from langchain_openai import ChatOpenAI

from ai_engine.core.config import Settings, get_settings
from ai_engine.llm.factory import (
    LlmNotConfiguredError,
    describe_model,
    extract_message_text,
    get_chat_model,
    require_configured_chat_model,
    reset_chat_model_cache,
)


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    get_settings.cache_clear()
    reset_chat_model_cache()


def test_factory_constructs_a_chat_openai_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4.1-mini")

    model = get_chat_model(
        provider="openai", api_key="sk-test-not-a-real-key", model_name="gpt-4.1-mini"
    )

    assert isinstance(model, ChatOpenAI)
    assert model.model_name == "gpt-4.1-mini"


def test_default_provider_is_openai_hosted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    assert Settings().resolved_base_url is None
    assert describe_model()["provider"] == "openai"


def test_base_url_can_be_overridden_without_touching_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "http://vllm.internal:8000/v1/")

    described = describe_model()

    assert described["base_url"] == "http://vllm.internal:8000/v1"
    assert described["provider"] == "openai-compatible"


def test_model_is_cached_across_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")

    kwargs = {
        "provider": "openai",
        "api_key": "sk-test-not-a-real-key",
        "model_name": "gpt-4.1-mini",
    }
    assert get_chat_model(**kwargs) is get_chat_model(**kwargs)


def test_construction_succeeds_without_a_key_but_calling_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "")

    # Constructing is allowed: startup must not require credentials.
    assert isinstance(
        get_chat_model(provider="openai", api_key="", model_name="gpt-4.1-mini"),
        ChatOpenAI,
    )
    assert describe_model()["configured"] is False

    with pytest.raises(LlmNotConfiguredError):
        require_configured_chat_model()


def test_extract_message_text_flattens_anthropic_blocks() -> None:
    message = AIMessage(
        content=[
            {"type": "thinking", "thinking": "Let me reason about this."},
            {"type": "text", "text": '{"findings": []}'},
        ]
    )

    assert extract_message_text(message) == '{"findings": []}'


def test_extract_message_text_passes_openai_string_through() -> None:
    message = AIMessage(content="plain answer")

    assert extract_message_text(message) == "plain answer"
