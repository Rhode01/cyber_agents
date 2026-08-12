"""Exception-translation tests for `app.llm.structured`.

Every clause in that translator is a claim about the installed SDK, and a wrong claim
produces a handler that compiles and never fires. Two of them were wrong in my own notes
before being checked here:

* `LengthFinishReasonError` and `ContentFilterFinishReasonError` subclass `OpenAIError`
  **directly**, not `APIError`, so `except openai.APIError` misses both;
* `OpenAIRefusalError` does not exist in `openai` at all - it lives in `langchain_openai`,
  and because `include_raw=True` wraps the parser in a fallback, a refusal arrives as a
  *value* in `parsing_error` rather than as a raise.

The retry policy is asserted by counting calls, because "exactly one repair turn" and
"refusals are never retried" are both about how many requests get billed.
"""

from __future__ import annotations

from typing import Any

import httpx
import openai
import pytest
from langchain_openai.chat_models.base import OpenAIRefusalError
from pydantic import BaseModel, ConfigDict, ValidationError

from app.llm.errors import (
    AssessmentConfigurationError,
    AssessmentRateLimitedError,
    AssessmentRefusedError,
    AssessmentTimeoutError,
    AssessmentUnavailableError,
    AssessmentUnparsableError,
)
from app.llm.structured import invoke_structured

REQUEST = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")


def response(status: int) -> httpx.Response:
    return httpx.Response(status, request=REQUEST, json={"error": {"message": "nope"}})


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str


class FakeRunnable:
    """Stands in for the runnable `with_structured_output` returns."""

    def __init__(self, outcomes: list[Any]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def ainvoke(self, messages: list[Any]) -> Any:
        del messages
        self.calls += 1
        outcome = self._outcomes.pop(0) if self._outcomes else self._outcomes
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeModel:
    """Stands in for a chat model, recording how it was asked for structure."""

    def __init__(self, outcomes: list[Any]) -> None:
        self.runnable = FakeRunnable(outcomes)
        self.kwargs: dict[str, Any] = {}

    def with_structured_output(self, schema: Any, **kwargs: Any) -> FakeRunnable:
        self.kwargs = {"schema": schema, **kwargs}
        return self.runnable


def raw(text: str) -> Any:
    """A stand-in for the AIMessage `include_raw` returns alongside the parse."""
    return type("_Msg", (), {"content": text})()


async def call(outcomes: list[Any], *, repair: Any = None) -> Any:
    model = FakeModel(outcomes)
    return await invoke_structured(
        model=model,  # type: ignore[arg-type]
        schema=Answer,
        messages=[],
        label="test",
        repair=repair,
    )


def validation_error() -> ValidationError:
    try:
        Answer.model_validate({"wrong": "shape"})
    except ValidationError as err:
        return err
    raise AssertionError("Answer.model_validate should have failed")


# ---------------------------------------------------------------------------
# how the model is asked
# ---------------------------------------------------------------------------


async def test_structure_is_requested_with_json_schema_and_include_raw() -> None:
    """`include_raw` is what puts the model's actual bytes in the log on a parse failure."""
    model = FakeModel([{"parsed": Answer(verdict="clean"), "parsing_error": None}])

    await invoke_structured(
        model=model, schema=Answer, messages=[], label="test", repair=None  # type: ignore[arg-type]
    )

    assert model.kwargs["method"] == "json_schema"
    assert model.kwargs["include_raw"] is True
    # `strict` is deliberately not passed - strict-safety is enforced by our own schema
    # guard rather than by a kwarg in someone else's code.
    assert "strict" not in model.kwargs


async def test_a_clean_parse_is_returned() -> None:
    result = await call([{"parsed": Answer(verdict="phishing"), "parsing_error": None}])

    assert isinstance(result, Answer)
    assert result.verdict == "phishing"


# ---------------------------------------------------------------------------
# transport failures - ordering matters
# ---------------------------------------------------------------------------


async def test_a_timeout_becomes_a_gateway_timeout() -> None:
    """`APITimeoutError` is a subclass of `APIConnectionError`, so it must be caught first
    or a timeout is reported as a generic connection failure."""
    with pytest.raises(AssessmentTimeoutError) as caught:
        await call([openai.APITimeoutError(request=REQUEST)])

    assert caught.value.status_code == 504
    assert "OPENAI_TIMEOUT_SECONDS" in caught.value.hint


async def test_a_connection_failure_is_unavailable() -> None:
    with pytest.raises(AssessmentUnavailableError) as caught:
        await call([openai.APIConnectionError(message="refused", request=REQUEST)])

    assert caught.value.status_code == 502


async def test_a_rate_limit_becomes_503_not_429() -> None:
    """The caller did not cause this and cannot fix it by slowing down."""
    with pytest.raises(AssessmentRateLimitedError) as caught:
        await call([openai.RateLimitError("slow down", response=response(429), body=None)])

    assert caught.value.status_code == 503


async def test_a_bad_request_becomes_500_because_it_is_ours() -> None:
    """A 400 from the provider means our schema or size cap is wrong, not the caller's
    request. Reporting it as a client error would point the blame at the wrong party."""
    with pytest.raises(AssessmentConfigurationError) as caught:
        await call([openai.BadRequestError("bad schema", response=response(400), body=None)])

    assert caught.value.status_code == 500
    assert "strict mode forbids" in caught.value.hint


async def test_an_authentication_failure_is_a_configuration_error() -> None:
    with pytest.raises(AssessmentConfigurationError):
        await call([openai.AuthenticationError("no key", response=response(401), body=None)])


async def test_an_upstream_server_error_is_unavailable() -> None:
    with pytest.raises(AssessmentUnavailableError):
        await call([openai.InternalServerError("boom", response=response(500), body=None)])


async def test_a_generic_api_error_is_unavailable() -> None:
    with pytest.raises(AssessmentUnavailableError):
        await call([openai.APIError("generic", REQUEST, body=None)])


# ---------------------------------------------------------------------------
# the two that are not APIError subclasses
# ---------------------------------------------------------------------------


def test_the_finish_reason_errors_really_do_bypass_api_error() -> None:
    """Documents the fact the handlers depend on, checked against the installed SDK.

    If a future release makes these APIError subclasses, the dedicated clauses become
    unreachable - and this assertion is what says so.
    """
    assert not issubclass(openai.LengthFinishReasonError, openai.APIError)
    assert not issubclass(openai.ContentFilterFinishReasonError, openai.APIError)
    assert issubclass(openai.LengthFinishReasonError, openai.OpenAIError)


async def test_a_truncated_response_is_unparsable() -> None:
    # The constructor reads `completion.usage` to build its message, so the stand-in needs
    # both attributes - a bare object raises AttributeError inside openai itself.
    completion = type("_Completion", (), {"choices": [], "usage": None})()

    with pytest.raises(AssessmentUnparsableError) as caught:
        await call([openai.LengthFinishReasonError(completion=completion)])

    assert "output limit" in str(caught.value)


async def test_a_content_filtered_response_is_unparsable() -> None:
    with pytest.raises(AssessmentUnparsableError) as caught:
        await call([openai.ContentFilterFinishReasonError()])

    assert "content filter" in str(caught.value)


# ---------------------------------------------------------------------------
# refusals - never retried
# ---------------------------------------------------------------------------


async def test_a_refusal_arrives_as_a_parsing_error_and_is_translated() -> None:
    with pytest.raises(AssessmentRefusedError) as caught:
        await call(
            [
                {
                    "parsed": None,
                    "parsing_error": OpenAIRefusalError("I cannot help with that"),
                    "raw": raw(""),
                }
            ]
        )

    assert caught.value.status_code == 502
    assert "I cannot help with that" in str(caught.value)


async def test_a_refusal_is_never_retried_even_with_a_repair_available() -> None:
    """At temperature 0 an identical prompt refuses identically, so a repair turn would
    spend money to be told no twice."""
    model = FakeModel(
        [{"parsed": None, "parsing_error": OpenAIRefusalError("no"), "raw": raw("")}]
    )

    with pytest.raises(AssessmentRefusedError):
        await invoke_structured(
            model=model,  # type: ignore[arg-type]
            schema=Answer,
            messages=[],
            label="test",
            repair=lambda _text: [],
        )

    assert model.runnable.calls == 1


# ---------------------------------------------------------------------------
# the repair turn - exactly one
# ---------------------------------------------------------------------------


async def test_a_validation_failure_without_a_repair_fails_immediately() -> None:
    model = FakeModel(
        [{"parsed": None, "parsing_error": validation_error(), "raw": raw("{bad}")}]
    )

    with pytest.raises(AssessmentUnparsableError):
        await invoke_structured(
            model=model, schema=Answer, messages=[], label="test", repair=None  # type: ignore[arg-type]
        )

    assert model.runnable.calls == 1


async def test_one_repair_turn_can_recover_a_validation_failure() -> None:
    model = FakeModel(
        [
            {"parsed": None, "parsing_error": validation_error(), "raw": raw("{bad}")},
            {"parsed": Answer(verdict="suspicious"), "parsing_error": None},
        ]
    )

    result = await invoke_structured(
        model=model,  # type: ignore[arg-type]
        schema=Answer,
        messages=[],
        label="test",
        repair=lambda _text: [],
    )

    assert result.verdict == "suspicious"
    assert model.runnable.calls == 2


async def test_the_repair_turn_happens_exactly_once() -> None:
    """Not a loop. `with_retry` is deliberately unused - it re-sends a byte-identical
    prompt, which at temperature 0 reproduces the failure and bills for it."""
    model = FakeModel(
        [
            {"parsed": None, "parsing_error": validation_error(), "raw": raw("{bad}")},
            {"parsed": None, "parsing_error": validation_error(), "raw": raw("{still bad}")},
        ]
    )

    with pytest.raises(AssessmentUnparsableError) as caught:
        await invoke_structured(
            model=model,  # type: ignore[arg-type]
            schema=Answer,
            messages=[],
            label="test",
            repair=lambda _text: [],
        )

    assert model.runnable.calls == 2
    assert "after one repair turn" in str(caught.value)


async def test_a_transport_failure_on_the_repair_turn_is_translated() -> None:
    model = FakeModel(
        [
            {"parsed": None, "parsing_error": validation_error(), "raw": raw("{bad}")},
            openai.APITimeoutError(request=REQUEST),
        ]
    )

    with pytest.raises(AssessmentTimeoutError):
        await invoke_structured(
            model=model,  # type: ignore[arg-type]
            schema=Answer,
            messages=[],
            label="test",
            repair=lambda _text: [],
        )


async def test_the_previous_answer_is_replayed_to_the_model_on_repair() -> None:
    """The model sees its own bad output, so it can correct rather than start over."""
    seen: list[list[Any]] = []

    class Recording(FakeRunnable):
        async def ainvoke(self, messages: list[Any]) -> Any:
            seen.append(list(messages))
            return await super().ainvoke(messages)

    model = FakeModel([])
    model.runnable = Recording(
        [
            {"parsed": None, "parsing_error": validation_error(), "raw": raw("{oops}")},
            {"parsed": Answer(verdict="clean"), "parsing_error": None},
        ]
    )

    await invoke_structured(
        model=model,  # type: ignore[arg-type]
        schema=Answer,
        messages=[],
        label="test",
        repair=lambda _text: [],
    )

    assert len(seen) == 2
    assert any("{oops}" in str(getattr(item, "content", "")) for item in seen[1])


# ---------------------------------------------------------------------------
# the shape contract
# ---------------------------------------------------------------------------


async def test_a_non_dict_result_is_a_configuration_error() -> None:
    """`include_raw=True` guarantees a dict. If that changes, say so plainly rather than
    raising an AttributeError three frames away."""
    with pytest.raises(AssessmentConfigurationError, match="include_raw"):
        await call([Answer(verdict="clean")])


def test_every_error_carries_a_status_and_a_hint() -> None:
    """The hint is what an operator reads; an empty one makes the type pointless."""
    for error_type in (
        AssessmentTimeoutError,
        AssessmentUnavailableError,
        AssessmentRateLimitedError,
        AssessmentConfigurationError,
        AssessmentUnparsableError,
        AssessmentRefusedError,
    ):
        assert 400 <= error_type.status_code <= 599
        assert error_type.hint.strip(), f"{error_type.__name__} has no hint"
