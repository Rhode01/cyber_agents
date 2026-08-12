"""End-to-end tests for the phishing graph, with the model replaced by a double.

The assessor is injected through `config["configurable"]`, which is the seam
`assessor.resolve_assessor` reads. No API key, no network, no MCP.

Two properties here carry the safety argument, and both are asserted against a *hostile*
double - one that tries to lower the severity and to name evidence that does not exist:

* the model may raise severity above the deterministic floor, never below it;
* an indicator id the model invents never reaches a finding.

A cooperative double would pass whatever the code did.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from cyber_contracts import (
    AuthResults,
    EmailAddress,
    FindingType,
    MessageFormat,
    NormalizedMessage,
    Severity,
)

from app.agents.common.assessment_schema import (
    ConfidenceBand,
    InjectionReport,
    InjectionSignal,
)
from app.agents.phishing.assessment_schema import PhishingAssessment, PhishingVerdict
from app.agents.phishing.assessor import ASSESSOR_CONFIG_KEY
from app.agents.phishing.graph import GRAPH
from app.agents.phishing.indicators import Indicator
from app.agents.phishing.scoring import Score
from app.agents.phishing.state import initial_phishing_state

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "messages"


def load(name: str) -> NormalizedMessage:
    return NormalizedMessage.model_validate(
        json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    )


def assessor(
    *,
    severity: str = "high",
    verdict: PhishingVerdict = PhishingVerdict.phishing,
    injection: InjectionSignal = InjectionSignal.none,
    ranked: list[str] | None = None,
    confidence: ConfidenceBand = ConfidenceBand.high,
) -> Any:
    """A deterministic stand-in for the model.

    ``ranked=None`` means "echo back the real ids", which is the cooperative case. Tests
    that care about reconciliation pass ids explicitly, including invented ones.
    """

    async def fake(
        indicators: Sequence[Indicator],
        score: Score,
        *,
        source: str,
        asset: str | None,
        body_excerpt: str,
        enrichment: dict[str, Any] | None,
        context: dict[str, Any],
    ) -> PhishingAssessment:
        del score, source, asset, body_excerpt, enrichment, context
        return PhishingAssessment(
            injection=InjectionReport(signal=injection, note="stand-in note"),
            key_indicator_ids=(
                ranked
                if ranked is not None
                else [indicator.indicator_id for indicator in indicators]
            ),
            explanation="A stand-in explanation naming paypa1.com and invoice.pdf.exe.",
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            title="Stand-in title",
            recommendation="Block the sender and delete the message.",
        )

    return fake


async def run(name: str, *, config_extra: dict[str, Any] | None = None, **kwargs: Any) -> Any:
    state = initial_phishing_state(
        message=load(name), source="eml-upload", asset=kwargs.pop("asset", None)
    )
    configurable: dict[str, Any] = {ASSESSOR_CONFIG_KEY: assessor(**kwargs)}
    configurable.update(config_extra or {})
    return await GRAPH.ainvoke(state, config={"configurable": configurable})


# ---------------------------------------------------------------------------
# the happy path
# ---------------------------------------------------------------------------


async def test_a_phishing_message_produces_one_primary_finding() -> None:
    result = await run("phish")

    primary = [
        finding
        for finding in result["findings"]
        if finding.finding_type is FindingType.phishing_message
    ]
    assert len(primary) == 1, "the unit of analyst action is the message, not the indicator"

    finding = primary[0]
    assert finding.title == "Stand-in title"
    assert finding.description.startswith("A stand-in explanation")
    assert finding.recommendation
    assert finding.asset == "service@paypa1.com"


async def test_indicators_travel_in_evidence_not_as_separate_findings() -> None:
    result = await run("phish")
    finding = result["findings"][0]

    indicators = finding.evidence["indicators"]
    assert len(indicators) > 5
    assert {"indicator_id", "rule_id", "category", "fact", "weight"} <= set(indicators[0])


async def test_the_feature_vector_is_stored_for_later_training() -> None:
    """Every analysed message becomes one training row; that is the ML seam."""
    result = await run("phish")

    features = result["findings"][0].evidence["rule_engine"]["features"]
    assert features["indicator_count"] > 0
    assert "cat_authentication_score" in features


async def test_the_graph_runs_the_canonical_nodes() -> None:
    nodes = set(GRAPH.get_graph().nodes)

    assert {"normalize", "detect", "enrich", "score", "reason", "emit_findings"} <= nodes


async def test_normalized_counts_are_recorded() -> None:
    result = await run("phish")

    assert result["normalized"]["links"] == 2
    assert result["normalized"]["attachments"] == 1


# ---------------------------------------------------------------------------
# the severity floor - the model may raise, never lower
# ---------------------------------------------------------------------------


async def test_the_model_cannot_lower_severity_below_the_floor() -> None:
    """The hostile case: a message crafted to talk its own severity down.

    Enforced in code rather than by the prompt, because a prompt is a request and this is
    a guarantee.
    """
    result = await run("phish", severity="info", verdict=PhishingVerdict.clean)

    finding = result["findings"][0]
    floor = result["score"].band

    assert finding.severity is floor
    assert finding.severity is Severity.critical
    assert finding.evidence["model"]["severity_floor_enforced"] is True


async def test_the_model_can_raise_severity_above_the_floor() -> None:
    quiet = NormalizedMessage(
        format=MessageFormat.email_mime,
        subject="Please review",
        body_text="Nothing much.",
        sender=EmailAddress(display_name="", address="a@b.example", domain="b.example"),
        auth=AuthResults(spf="softfail", dkim="none", dmarc="none", present=True),
    )
    state = initial_phishing_state(message=quiet, source="eml-upload")

    result = await GRAPH.ainvoke(
        state,
        config={"configurable": {ASSESSOR_CONFIG_KEY: assessor(severity="critical")}},
    )

    finding = result["findings"][0]
    assert finding.severity is Severity.critical
    assert finding.severity != result["score"].band
    assert finding.evidence["model"]["severity_floor_enforced"] is False


async def test_an_unrecognised_model_severity_falls_back_to_the_floor() -> None:
    """Models write "Sev-1" and "worst". Unrecognised means "use ours", not "use info"."""
    result = await run("phish", severity="catastrophic")

    assert result["findings"][0].severity is result["score"].band


async def test_confidence_comes_from_the_band_not_from_the_model() -> None:
    """A float on the wire is unbounded under strict mode, so the band is authoritative."""
    high = await run("phish", confidence=ConfidenceBand.high)
    low = await run("phish", confidence=ConfidenceBand.low)

    assert high["findings"][0].confidence > low["findings"][0].confidence
    assert high["findings"][0].confidence < 1.0


# ---------------------------------------------------------------------------
# reconciliation - invented evidence never survives
# ---------------------------------------------------------------------------


async def test_an_invented_indicator_id_never_reaches_a_finding() -> None:
    """An unknown id is the model asserting evidence no rule found.

    Accepting one would let a crafted message manufacture a finding, which is the whole
    reason the ids are opaque and content-addressed.
    """
    result = await run("phish", ranked=["ind_fake01", "ind_fake02"])

    finding = result["findings"][0]
    stored_ids = {entry["indicator_id"] for entry in finding.evidence["indicators"]}

    assert "ind_fake01" not in stored_ids
    assert "ind_fake02" not in stored_ids
    assert finding.evidence["ranking"]["unknown_ids_dropped"] == ["ind_fake01", "ind_fake02"]
    assert finding.evidence["ranking"]["model_ranked_ids"] == []


async def test_every_real_indicator_survives_a_partial_ranking() -> None:
    """Ranking decides order, never membership."""
    baseline = await run("phish")
    all_ids = [entry["indicator_id"] for entry in baseline["findings"][0].evidence["indicators"]]

    result = await run("phish", ranked=[all_ids[3]])
    ordered = [entry["indicator_id"] for entry in result["findings"][0].evidence["indicators"]]

    assert ordered[0] == all_ids[3], "the ranked id leads"
    assert set(ordered) == set(all_ids), "nothing was dropped"


async def test_duplicate_ids_are_collapsed() -> None:
    baseline = await run("phish")
    first = baseline["findings"][0].evidence["indicators"][0]["indicator_id"]

    result = await run("phish", ranked=[first, first, first])

    ranking = result["findings"][0].evidence["ranking"]
    assert ranking["model_ranked_ids"] == [first]
    assert len(ranking["duplicate_ids"]) == 2


# ---------------------------------------------------------------------------
# injection - two independent detectors, either sufficient
# ---------------------------------------------------------------------------


async def test_the_rule_detector_alone_raises_an_injection_finding() -> None:
    """A model reporting `none` must not be able to suppress it.

    A model that has been successfully steered is exactly the one that reports none.
    """
    result = await run("injection", injection=InjectionSignal.none)

    injection = [
        finding
        for finding in result["findings"]
        if finding.finding_type is FindingType.prompt_injection_attempt
    ]
    assert len(injection) == 1
    assert injection[0].severity is Severity.high
    assert injection[0].evidence["rule_detector_fired"] is True
    assert injection[0].evidence["model_detector_signal"] == "none"


async def test_the_model_detector_alone_raises_an_injection_finding() -> None:
    """And the converse: a phrasing no pattern anticipated, noticed by the model."""
    result = await run("phish", injection=InjectionSignal.suspected)

    injection = next(
        finding
        for finding in result["findings"]
        if finding.finding_type is FindingType.prompt_injection_attempt
    )
    assert injection.evidence["rule_detector_fired"] is False
    assert injection.evidence["model_detector_signal"] == "suspected"


async def test_the_primary_verdict_is_still_produced_alongside_an_injection_finding() -> None:
    """An injection attempt must not derail the assessment it was trying to derail."""
    result = await run("injection")

    types = [finding.finding_type for finding in result["findings"]]
    assert FindingType.phishing_message in types
    assert FindingType.prompt_injection_attempt in types


async def test_no_injection_finding_when_neither_detector_fires() -> None:
    result = await run("phish", injection=InjectionSignal.none)

    types = [finding.finding_type for finding in result["findings"]]
    assert FindingType.prompt_injection_attempt not in types


# ---------------------------------------------------------------------------
# clean mail
# ---------------------------------------------------------------------------


async def test_clean_mail_still_produces_one_informational_finding() -> None:
    """"Analysed, nothing found" must never look the same as "never analysed".

    The latter is what a null verdict on the intake row means, and an empty finding list
    would be indistinguishable from a failure in the UI.
    """
    result = await run("basic")

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding.severity is Severity.info
    assert finding.finding_type is FindingType.phishing_message
    assert finding.evidence["verdict"] == "clean"
    assert "no indicator fired" in finding.description


async def test_no_model_is_called_when_nothing_fired() -> None:
    """Cost control and a security property at once: unremarkable mail is never shown
    to a model."""
    calls: list[int] = []

    async def counting(*args: Any, **kwargs: Any) -> PhishingAssessment:
        calls.append(1)
        raise AssertionError("the model must not be called when no indicator fired")

    state = initial_phishing_state(message=load("basic"), source="eml-upload")
    result = await GRAPH.ainvoke(
        state, config={"configurable": {ASSESSOR_CONFIG_KEY: counting}}
    )

    assert calls == []
    assert len(result["findings"]) == 1


# ---------------------------------------------------------------------------
# url submissions
# ---------------------------------------------------------------------------


async def test_a_url_submission_is_typed_as_a_malicious_url_finding() -> None:
    submitted = NormalizedMessage(
        format=MessageFormat.url,
        sender=EmailAddress(display_name="", address="", domain=""),
        auth=AuthResults(spf="none", dkim="none", dmarc="none", present=False),
        links=[
            {
                "url": "http://45.61.188.203/paypal/login",
                "scheme": "http",
                "host": "45.61.188.203",
                "anchor_text": "",
            }
        ],
    )
    state = initial_phishing_state(
        message=submitted, source="url-submission", asset="http://45.61.188.203/paypal/login"
    )

    result = await GRAPH.ainvoke(
        state, config={"configurable": {ASSESSOR_CONFIG_KEY: assessor()}}
    )

    assert result["findings"][0].finding_type is FindingType.malicious_url
    assert result["findings"][0].asset == "http://45.61.188.203/paypal/login"


# ---------------------------------------------------------------------------
# the capped analysis is never silent about being capped
# ---------------------------------------------------------------------------


async def test_a_capped_analysis_says_so_in_the_evidence(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """A partial analysis must not read as a complete one."""
    from app.core.config import Settings, get_settings

    original = get_settings()
    capped = Settings(**{**original.model_dump(), "phishing_max_indicators": 3})
    monkeypatch.setattr("app.agents.phishing.nodes.get_settings", lambda: capped)

    result = await run("phish")

    finding = result["findings"][0]
    assert len(finding.evidence["indicators"]) == 3
    assert finding.evidence["capped"]["dropped_indicator_count"] > 0
    assert finding.evidence["capped"]["dropped_indicator_ids"]


# ---------------------------------------------------------------------------
# the body never travels in the shared state field
# ---------------------------------------------------------------------------


async def test_the_message_body_is_not_placed_in_raw_input() -> None:
    """`raw_input` is a provenance line, not the payload.

    Putting the body there would push it into the shared AgentState field other code
    logs and previews, quietly widening the injection surface.
    """
    result = await run("phish")

    assert "Dear Customer" not in result["raw_input"]
    assert "link(s)" in result["raw_input"]
