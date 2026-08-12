"""The seam where the model is called, and where tests replace it.

``resolve_assessor`` reads an optional callable out of the graph config. Production omits
it and gets the real one; a test injects a typed double via
``{"configurable": {ASSESSOR_CONFIG_KEY: fake}}``.

Chosen over the two obvious alternatives:

* **Monkeypatching** patches an import site rather than an interface, so the string
  being patched rots the moment imports are reshuffled - and mypy never checks the
  double against what it replaces.
* **``langchain_core``'s fake chat models** inherit the *generic tool-calling*
  ``with_structured_output``, not the ``json_schema`` path this agent uses. A test built
  on one exercises LangChain's parser instead of our reconciliation, which is the part
  that can actually be wrong.

**The default is real.** A test that passes because production quietly substituted a
fake is the exact failure this design exists to prevent, so there is no "if testing"
branch anywhere below.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final, Protocol

from langchain_core.runnables import RunnableConfig

from app.agents.phishing.assessment_schema import PhishingAssessment
from app.agents.phishing.indicators import Indicator
from app.agents.phishing.prompt import build_assess_messages, build_repair_messages
from app.agents.phishing.scoring import Score
from app.core.logging import get_logger
from app.llm.factory import require_configured_chat_model
from app.llm.structured import invoke_structured

logger = get_logger(__name__)

ASSESSOR_CONFIG_KEY: Final = "phishing_assessor"


class Assessor(Protocol):
    """Turns established indicators into an analyst-facing write-up."""

    async def __call__(
        self,
        indicators: Sequence[Indicator],
        score: Score,
        *,
        source: str,
        asset: str | None,
        body_excerpt: str,
        enrichment: dict[str, Any] | None,
        context: dict[str, Any],
    ) -> PhishingAssessment: ...


async def assess_with_model(
    indicators: Sequence[Indicator],
    score: Score,
    *,
    source: str,
    asset: str | None,
    body_excerpt: str,
    enrichment: dict[str, Any] | None,
    context: dict[str, Any],
) -> PhishingAssessment:
    """The real assessor: one structured call, with one repair turn available.

    ``require_configured_chat_model`` raises ``LlmNotConfiguredError`` before a prompt is
    built, so a deployment with no key fails on the first request rather than after a
    timeout - and the backend records that reason on the intake row instead of showing a
    verdict nobody should trust.
    """
    model = require_configured_chat_model(context=context)
    messages = build_assess_messages(
        indicators,
        score,
        source=source,
        asset=asset,
        body_excerpt=body_excerpt,
        enrichment=enrichment,
    )

    logger.info(
        "phishing.assess.calling_model",
        indicators=len(indicators),
        floor=score.band.value,
        enriched=bool(enrichment),
    )
    return await invoke_structured(
        model=model,
        schema=PhishingAssessment,
        messages=messages,
        label="phishing.assess",
        repair=build_repair_messages,
    )


def resolve_assessor(config: RunnableConfig) -> Assessor:
    """The assessor for this run: the injected one if present, otherwise the real one.

    Narrows ``Any`` once, here, so no node has to. The annotation on the caller's
    ``config`` parameter must be spelled exactly ``RunnableConfig`` - LangGraph matches
    it as a string against a whitelist, and a variant like ``RunnableConfig | None``
    warns and then silently declines to inject, which would disable this seam without
    failing a single test.
    """
    configurable = config.get("configurable") or {}
    injected = configurable.get(ASSESSOR_CONFIG_KEY)
    if injected is None:
        return assess_with_model
    if not callable(injected):
        msg = f"{ASSESSOR_CONFIG_KEY} must be callable, got {type(injected).__name__}"
        raise TypeError(msg)
    logger.info("phishing.assess.using_injected_assessor")
    return injected  # type: ignore[no-any-return]
