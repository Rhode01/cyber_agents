"""The vocabulary everything above the model SDK speaks.

Third-party exceptions are quarantined in ``app.llm.structured``, which is the only
module that imports ``openai``. Everything else - nodes, routers, tests - raises and
catches the types defined here. That boundary is what lets the SDK be upgraded, or
swapped for another provider, without a single node changing.

Each error carries the HTTP status it should become and a ``hint`` written for the
operator who has to fix it. The status choices are deliberate and two of them are
not the obvious ones:

* **A bad request becomes a 500, not a 4xx.** The caller sent a valid
  ``PhishingAnalyzeRequest``; a 400 from the provider means *our* schema or size cap
  is wrong. Reporting it as a client error would point the blame at the wrong party.
* **A rate limit becomes a 503, not a 429.** The backend has no retry logic yet, so
  answering 429 would tell a client to slow down about a limit it did not cause and
  cannot influence. 503 with a hint is honest: try again later, it is us.

There is deliberately no generic "assessment failed". Every failure mode an
operator can act on differently gets its own type, because the whole point of
translating is to stop "something went wrong" from being the only thing we can say.
"""

from __future__ import annotations


class AssessmentError(RuntimeError):
    """An assessment could not be produced.

    Subclasses set ``status_code`` and ``hint``. Both are class attributes rather
    than constructor arguments so a raise site cannot accidentally disagree with
    the handler about what a given failure means.
    """

    status_code: int = 502
    hint: str = ""


class LlmNotConfiguredError(AssessmentError):
    """No API key is present, so a live call could not succeed.

    Raised **pre-flight**, before a prompt is built, so a misconfigured deployment
    fails on the first request instead of after a 60-second timeout.
    """

    status_code = 503
    hint = (
        "Set OPENAI_API_KEY (or ANTHROPIC_API_KEY with LLM_PROVIDER=anthropic) in "
        "the ai.engine's environment. Nothing is assessed without it - findings are "
        "never produced from rules alone, because a rule-only result reads as a "
        "complete assessment while being a partial one."
    )


class AssessmentUnavailableError(AssessmentError):
    """The provider could not be reached, or failed on its own side.

    Covers timeouts, connection failures and upstream 5xx. The SDK has already
    exhausted its own retries by the time this is raised, so the caller should
    surface it rather than loop.
    """

    status_code = 502
    hint = (
        "The model provider was unreachable or returned a server error. Check "
        "network egress and the provider's status page, then re-submit."
    )


class AssessmentTimeoutError(AssessmentUnavailableError):
    """The provider did not answer within the configured timeout.

    Separate from its parent only for the status code: a gateway timeout is the
    accurate answer and it tells an operator to look at latency rather than at
    connectivity.
    """

    status_code = 504
    hint = (
        "The model did not answer within OPENAI_TIMEOUT_SECONDS. Raise it, or "
        "reduce PHISHING_MAX_INDICATORS so there is less to reason about."
    )


class AssessmentRateLimitedError(AssessmentError):
    """The provider rate-limited us."""

    status_code = 503
    hint = (
        "The model provider is rate-limiting this key. Re-submit later, or raise "
        "the account's limit. Reported as 503 rather than 429 because the caller "
        "did not cause this and cannot fix it by slowing down."
    )


class AssessmentConfigurationError(AssessmentError):
    """The provider rejected the request as malformed.

    Ours to fix, not the caller's - see the module docstring. Usually a schema that
    strict Structured Outputs will not accept, or a prompt over the context limit.
    """

    status_code = 500
    hint = (
        "The provider rejected our request. Most likely the assessment schema has "
        "grown a construct strict mode forbids (a default, an Optional, or a Field "
        "constraint), or the prompt exceeded the context window. "
        "tests/unit/test_assessment_schema.py guards the first case."
    )


class AssessmentUnparsableError(AssessmentError):
    """The model answered, but not with something matching the schema.

    Raised after the one repair turn has also failed. The raw response is logged at
    the point of failure, so diagnosis does not depend on reproducing it.
    """

    status_code = 502
    hint = (
        "The model's response did not match the assessment schema, and the repair "
        "turn did not fix it. The raw response is in the logs under "
        "llm.structured.unparsable."
    )


class AssessmentRefusedError(AssessmentError):
    """The model declined to answer.

    **Never retried.** At temperature 0 an identical prompt reproduces a refusal,
    so a second call spends money to receive the same answer. Worth investigating
    rather than working around: a refusal on a phishing assessment is usually the
    model reacting to the injected content inside the fence, which is itself a
    finding.
    """

    status_code = 502
    hint = (
        "The model refused to answer. Not retried, because an identical prompt at "
        "temperature 0 refuses identically. The refusal text is logged under "
        "llm.structured.refused - on a phishing assessment it often means the "
        "submitted message contains content aimed at the model."
    )


class AssessmentIncompleteError(AssessmentError):
    """The model omitted things it was required to cover.

    Unused by the phishing agent, whose ranking list is a hint rather than a
    per-item obligation. Defined here because it is the one anomaly that loses
    information, and an agent that does require full coverage needs somewhere to
    raise from.
    """

    status_code = 502
    hint = (
        "The model did not cover every item it was asked to, and the repair turn "
        "did not recover them. See the logged missing ids."
    )
