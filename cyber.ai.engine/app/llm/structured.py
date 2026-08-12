"""The one place a model is asked for a structured answer.

This is the only module in the service that imports ``openai`` or reaches into
``langchain_openai``'s internals. Everything above it speaks ``app.llm.errors``, so
the SDK can move without a single node changing.

Verified against the installed packages (openai 2.52.0, langchain-openai 1.4.x)
rather than remembered, because three of these details are counter-intuitive and
each one silently disables a handler if you get it wrong:

1. **``LengthFinishReasonError`` and ``ContentFilterFinishReasonError`` subclass
   ``OpenAIError`` directly, not ``APIError``.** An ``except openai.APIError`` misses
   both, so a truncated or filtered response would escape as an unhandled 500.

2. **``APITimeoutError`` ⊂ ``APIConnectionError`` ⊂ ``APIError``.** The narrow ones
   must come first or a timeout is reported as a generic connection failure.

3. **``OpenAIRefusalError`` lives in ``langchain_openai``, not ``openai``** - there is
   nothing refusal-shaped in the openai package at all. It is raised by
   ``_oai_structured_outputs_parser``, which ``include_raw=True`` wraps in
   ``with_fallbacks(..., exception_key="parsing_error")``. So a refusal arrives as a
   *value* in ``parsing_error``, never as a raise. The model call itself sits outside
   that fallback, so transport errors do still raise. That split is what makes the
   two code paths below correct.

``include_raw=True`` is used so a parse failure yields the model's actual bytes in
the log instead of a bare 502 with nothing to diagnose.

``strict=`` is deliberately not passed. Strict-safety is enforced on our side
instead - the assessment schemas carry no defaults, no ``Optional`` and no ``Field``
constraints, and ``tests/unit/test_assessment_schema.py`` fails the build if one
appears. Relying on a kwarg to police that would put the guarantee in someone
else's code.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

import openai
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage

# Imported from langchain_openai on purpose - see point 3 above. If a future release
# moves it, this import fails loudly at startup, which is much better than a handler
# that quietly stops matching and turns every refusal into "unparsable".
from langchain_openai.chat_models.base import OpenAIRefusalError
from pydantic import BaseModel

from app.core.logging import get_logger
from app.llm.errors import (
    AssessmentConfigurationError,
    AssessmentRateLimitedError,
    AssessmentRefusedError,
    AssessmentTimeoutError,
    AssessmentUnavailableError,
    AssessmentUnparsableError,
)

logger = get_logger(__name__)

RAW_PREVIEW_CHARS = 2_000
"""How much of a bad response to log. Enough to diagnose, bounded so a runaway
generation cannot fill the log."""


def _preview(text: str) -> str:
    if len(text) <= RAW_PREVIEW_CHARS:
        return text
    return f"{text[:RAW_PREVIEW_CHARS]}... [{len(text) - RAW_PREVIEW_CHARS} more characters]"


def _raw_text(raw: object) -> str:
    """Flatten whatever came back into text for logging and repair.

    Anthropic returns content blocks and OpenAI returns a string, so this mirrors
    ``factory.extract_message_text`` without importing it - the two exist for
    different reasons and coupling them would make one hostage to the other.
    """
    content = getattr(raw, "content", raw)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


async def _ainvoke(runnable: Any, messages: Sequence[BaseMessage], label: str) -> dict[str, Any]:
    """Call the model, translating every third-party failure on the way out.

    Ordering is load-bearing: the narrow exception classes come before the ones they
    inherit from, and the two finish-reason errors are caught separately because
    they do not descend from ``APIError`` at all.
    """
    try:
        result = await runnable.ainvoke(list(messages))

    # -- not APIError subclasses; must be caught in their own right ---------
    except openai.LengthFinishReasonError as err:
        logger.warning("llm.structured.truncated", label=label, error=str(err))
        msg = (
            "The model hit its output limit before finishing the assessment. "
            "Reduce the number of indicators sent, or raise max_tokens."
        )
        raise AssessmentUnparsableError(msg) from err
    except openai.ContentFilterFinishReasonError as err:
        logger.warning("llm.structured.content_filtered", label=label, error=str(err))
        msg = "The provider's content filter stopped the response mid-generation."
        raise AssessmentUnparsableError(msg) from err

    # -- narrowest first ----------------------------------------------------
    except openai.APITimeoutError as err:
        logger.warning("llm.structured.timeout", label=label, error=str(err))
        msg = f"The model did not answer in time: {err}"
        raise AssessmentTimeoutError(msg) from err
    except openai.RateLimitError as err:
        logger.warning("llm.structured.rate_limited", label=label, error=str(err))
        msg = f"The model provider is rate-limiting this key: {err}"
        raise AssessmentRateLimitedError(msg) from err
    except openai.BadRequestError as err:
        # Ours, not the caller's: a valid request reached us and the provider
        # rejected what we built from it.
        logger.error("llm.structured.bad_request", label=label, error=str(err))
        msg = f"The provider rejected our request as malformed: {err}"
        raise AssessmentConfigurationError(msg) from err
    except openai.AuthenticationError as err:
        logger.error("llm.structured.auth_failed", label=label, error=str(err))
        msg = f"The provider rejected our credentials: {err}"
        raise AssessmentConfigurationError(msg) from err
    except openai.InternalServerError as err:
        logger.warning("llm.structured.upstream_error", label=label, error=str(err))
        msg = f"The model provider failed on its own side: {err}"
        raise AssessmentUnavailableError(msg) from err
    except openai.APIConnectionError as err:
        logger.warning("llm.structured.unreachable", label=label, error=str(err))
        msg = f"Could not reach the model provider: {err}"
        raise AssessmentUnavailableError(msg) from err
    except openai.APIError as err:
        logger.warning("llm.structured.api_error", label=label, error=str(err))
        msg = f"The model provider returned an error: {err}"
        raise AssessmentUnavailableError(msg) from err

    if not isinstance(result, dict):
        # include_raw=True guarantees a dict. If that ever changes, say so plainly
        # rather than raising an AttributeError three frames away.
        msg = f"expected include_raw=True to yield a dict, got {type(result).__name__}"
        raise AssessmentConfigurationError(msg)
    return result


async def invoke_structured[ModelT: BaseModel](
    *,
    model: BaseChatModel,
    schema: type[ModelT],
    messages: Sequence[BaseMessage],
    label: str,
    repair: Callable[[str], list[BaseMessage]] | None = None,
) -> ModelT:
    """Ask the model for one instance of ``schema``, or raise an ``AssessmentError``.

    Args:
        model: A configured chat model. Both ``ChatOpenAI`` and ``ChatAnthropic``
            support ``method="json_schema"``, so no provider branch is needed.
        schema: The Pydantic model to fill. Must be strict-safe: no defaults, no
            ``Optional``, no ``Field`` constraints.
        messages: The prompt. Untrusted content must already be fenced.
        label: Identifies this call in the logs, e.g. ``"phishing.assess"``.
        repair: Given the model's raw text, returns the extra messages for **one**
            repair turn. Applied only to schema-validation failures. Pass ``None`` to
            fail immediately instead.

    Returns:
        A validated ``schema`` instance.

    Raises:
        AssessmentRefusedError: the model declined. Never retried.
        AssessmentUnparsableError: the response did not match, and repair did not fix it.
        AssessmentTimeoutError, AssessmentUnavailableError, AssessmentRateLimitedError,
        AssessmentConfigurationError: as named.
    """
    runnable = model.with_structured_output(schema, method="json_schema", include_raw=True)

    result = await _ainvoke(runnable, messages, label)
    parsed = result.get("parsed")
    error = result.get("parsing_error")

    if isinstance(parsed, schema):
        return parsed

    raw_text = _raw_text(result.get("raw"))

    # A refusal is a decision, not a malformed answer. At temperature 0 an identical
    # prompt refuses identically, so a repair turn would spend money to be told no
    # twice - and on a phishing assessment a refusal usually means the fenced message
    # was aimed at the model, which is itself worth surfacing.
    if isinstance(error, OpenAIRefusalError):
        logger.warning("llm.structured.refused", label=label, refusal=_preview(str(error)))
        msg = f"The model refused to assess this input: {error}"
        raise AssessmentRefusedError(msg)

    if repair is None:
        logger.warning(
            "llm.structured.unparsable",
            label=label,
            error=str(error),
            raw=_preview(raw_text),
            repaired=False,
        )
        msg = f"The model's response did not match {schema.__name__}: {error}"
        raise AssessmentUnparsableError(msg)

    logger.info("llm.structured.repairing", label=label, error=str(error))

    # The repair prompt is built from our own data plus the model's own previous
    # answer. Nothing from inside the untrusted fence is quoted back into it, so a
    # crafted message cannot use the repair turn as a second injection attempt.
    repaired_messages: list[BaseMessage] = [
        *messages,
        AIMessage(content=raw_text),
        *repair(raw_text),
    ]

    retry = await _ainvoke(runnable, repaired_messages, f"{label}.repair")
    retry_parsed = retry.get("parsed")
    retry_error = retry.get("parsing_error")

    if isinstance(retry_parsed, schema):
        logger.info("llm.structured.repaired", label=label)
        return retry_parsed

    if isinstance(retry_error, OpenAIRefusalError):
        logger.warning("llm.structured.refused", label=label, refusal=_preview(str(retry_error)))
        msg = f"The model refused on the repair turn: {retry_error}"
        raise AssessmentRefusedError(msg)

    logger.warning(
        "llm.structured.unparsable",
        label=label,
        error=str(retry_error),
        raw=_preview(_raw_text(retry.get("raw"))),
        repaired=True,
    )
    msg = (
        f"The model's response did not match {schema.__name__} even after one "
        f"repair turn: {retry_error}"
    )
    raise AssessmentUnparsableError(msg)
