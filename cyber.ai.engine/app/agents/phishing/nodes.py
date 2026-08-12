"""Node functions for the phishing detection agent.

Flow: ``normalize → detect → enrich → score → reason → emit_findings``

Linear and deterministic. There is no conditional edge, and in particular **no shortcut
that skips the model when enough rules fire** - the previous implementation had one,
which meant the most suspicious mail was the mail that arrived with no explanation
attached. If rules fire, the model explains them; that is what it is for.

Node names keep the canonical ``normalize`` / ``reason`` / ``emit_findings`` so the
shared four-agent graph tests still apply.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cyber_contracts import (
    SEVERITY_ORDER,
    AgentKind,
    FindingCreate,
    FindingType,
    MessageFormat,
    Severity,
)
from langchain_core.runnables import RunnableConfig

from app.agents.common.assessment_schema import (
    CONFIDENCE_VALUES,
    ConfidenceBand,
    InjectionSignal,
)
from app.agents.common.findings import resolve_severity
from app.agents.phishing import enrich as enrichment_module
from app.agents.phishing import rules
from app.agents.phishing.assessor import resolve_assessor
from app.agents.phishing.indicators import Indicator, IndicatorCategory, sort_key
from app.agents.phishing.prompt import BODY_EXCERPT_CHARS
from app.agents.phishing.reconcile import reconcile
from app.agents.phishing.rules import injection as injection_rules
from app.agents.phishing.scoring import SCORER_CONFIG_KEY, Score
from app.agents.phishing.scoring import score as default_score
from app.agents.phishing.state import PhishingState
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


async def normalize(state: PhishingState) -> dict[str, Any]:
    """Record what arrived, for observability.

    The backend did the parsing and the contract already validated it, so there is
    nothing to re-parse here. This node puts counts in the log and in ``normalized``, and
    keeps the canonical node name the shared tests look for.
    """
    message = state["message"]
    normalized = {
        "format": message.format.value,
        "links": message.link_count,
        "distinct_link_hosts": len(message.link_hosts),
        "attachments": message.attachment_count,
        "body_chars": len(message.body_text),
        "html_present": message.body_html_present,
        "auth_present": message.auth.present,
        "received_hops": len(message.received_chain),
    }
    logger.info("phishing.normalize", **normalized)
    return {"normalized": normalized}


async def detect(state: PhishingState) -> dict[str, Any]:
    """Run the deterministic rule engine.

    Everything the agent will report is decided here. The cap is applied after sorting,
    so what gets dropped is always the weakest evidence - and the dropped ids are kept
    so ``emit_findings`` can say so out loud rather than silently narrowing the analysis.
    """
    settings = get_settings()
    found = rules.detect(state["message"])

    cap = settings.phishing_max_indicators
    kept, overflow = found[:cap], [indicator.indicator_id for indicator in found[cap:]]

    if overflow:
        logger.info(
            "phishing.detect.capped", found=len(found), kept=len(kept), dropped=len(overflow)
        )
    logger.info(
        "phishing.detect",
        indicators=len(kept),
        rules=sorted({indicator.rule_id for indicator in kept}),
    )
    return {"indicators": kept, "overflow_ids": overflow}


async def enrich(state: PhishingState) -> dict[str, Any]:
    """Add live context, if it is available and permitted.

    Every failure here is non-fatal, and the invariant is that enrichment can only
    **add** signal: it may append indicators, and it may never remove one or lower a
    score. A failed DNS lookup must not be able to make a phishing message look clean.
    """
    if not get_settings().phishing_enrichment_enabled:
        logger.info("phishing.enrich.disabled")
        return {"enrichment": {"available": False, "reason": "disabled by configuration"}}

    result = await enrichment_module.gather(
        message=state["message"], policy=state["policy"], existing=state["indicators"]
    )

    if not result.indicators:
        return {"enrichment": result.report}

    logger.info(
        "phishing.enrich.added_indicators",
        count=len(result.indicators),
        rules=sorted({indicator.rule_id for indicator in result.indicators}),
    )
    return {
        "enrichment": result.report,
        "indicators": _merge(state["indicators"], result.indicators),
    }


def _merge(existing: list[Indicator], added: list[Indicator]) -> list[Indicator]:
    """Fold enrichment indicators into the deterministic set, keeping order stable."""
    combined = {indicator.indicator_id: indicator for indicator in existing}
    for indicator in added:
        combined.setdefault(indicator.indicator_id, indicator)
    return sorted(combined.values(), key=sort_key)


async def score(state: PhishingState, config: RunnableConfig) -> dict[str, Any]:
    """Compute the deterministic severity floor.

    ``config: RunnableConfig`` is spelled exactly - LangGraph matches the annotation as a
    string against a whitelist, and a variant silently declines to inject, which would
    disable the scorer seam without failing a test.
    """
    configurable = config.get("configurable") or {}
    scorer = configurable.get(SCORER_CONFIG_KEY) or default_score

    computed: Score = scorer(state["indicators"])
    logger.info(
        "phishing.score",
        value=computed.value,
        floor=computed.band.value,
        indicators=len(state["indicators"]),
    )
    return {"score": computed}


async def reason(state: PhishingState, config: RunnableConfig) -> dict[str, Any]:
    """The only node that calls a model.

    Nothing is caught here. A missing key, a refusal, an unparseable answer - each raises
    an ``AssessmentError`` that ``core.http_errors`` turns into a status the backend
    records on the intake row. That is the fail-loudly path: an operator sees why there is
    no verdict, instead of a rule-only result that reads like a complete assessment.
    """
    indicators = state["indicators"]
    if not indicators:
        # Nothing fired, so there is nothing to explain and no call worth making.
        # emit_findings still produces an "analysed, nothing found" finding.
        logger.info("phishing.reason.skipped", reason="no indicators")
        return {}

    message = state["message"]
    assessor = resolve_assessor(config)
    assessment = await assessor(
        indicators,
        state["score"],
        source=state["source"],
        asset=state["asset"],
        body_excerpt=message.body_text[:BODY_EXCERPT_CHARS],
        enrichment=state.get("enrichment") or None,
        context=state.get("context", {}),
    )

    reconciliation = reconcile(indicators, assessment.key_indicator_ids)
    logger.info(
        "phishing.reason",
        verdict=assessment.verdict.value,
        model_severity=assessment.severity,
        injection=assessment.injection.signal.value,
        ranked=len(reconciliation.named_ids),
        unknown=len(reconciliation.unknown_ids),
    )
    return {"assessment": assessment, "reconciliation": reconciliation}


async def emit_findings(state: PhishingState) -> dict[str, Any]:
    """Join the assessment with the indicators into contract findings."""
    message = state["message"]
    indicators = state["indicators"]
    reconciliation = state.get("reconciliation")
    computed = state.get("score") or default_score(indicators)
    detected_at = datetime.now(UTC)

    ordered = list(reconciliation.ranked) if reconciliation else indicators
    finding_type = (
        FindingType.malicious_url
        if message.format is MessageFormat.url
        else FindingType.phishing_message
    )
    asset = state["asset"] or message.sender.address or None

    findings = [
        _primary_finding(
            state=state,
            ordered=ordered,
            computed=computed,
            finding_type=finding_type,
            asset=asset,
            detected_at=detected_at,
        )
    ]

    injection_finding = _injection_finding(
        state=state, ordered=ordered, asset=asset, detected_at=detected_at
    )
    if injection_finding is not None:
        findings.append(injection_finding)

    logger.info(
        "phishing.emit_findings",
        count=len(findings),
        severity=findings[0].severity.value,
        injection=injection_finding is not None,
    )
    return {"findings": findings}


def _final_severity(computed: Score, model_severity: str | None) -> tuple[Severity, bool]:
    """The severity to report, and whether the model tried to go below the floor.

    **The model may raise, never lower.** Enforced here rather than in the prompt, because
    a prompt is a request and this is a guarantee: a message crafted to talk its own
    severity down cannot succeed against a comparison.
    """
    floor = computed.band
    if model_severity is None:
        return floor, False

    proposed = resolve_severity(model_severity, default=floor)
    if SEVERITY_ORDER[proposed] < SEVERITY_ORDER[floor]:
        return floor, True
    return proposed, False


def _primary_finding(
    *,
    state: PhishingState,
    ordered: list[Indicator],
    computed: Score,
    finding_type: FindingType,
    asset: str | None,
    detected_at: datetime,
) -> FindingCreate:
    """One finding for the message as a whole.

    The unit of analyst action is the message - block the sender, delete it, warn the
    recipient - not the individual indicator, so indicators travel in ``evidence`` rather
    than becoming a dozen separate rows to triage.
    """
    message = state["message"]
    assessment = state.get("assessment")
    reconciliation = state.get("reconciliation")

    severity, undercut = _final_severity(computed, assessment.severity if assessment else None)
    if undercut and assessment is not None:
        logger.warning(
            "phishing.severity_floor_enforced",
            model_severity=assessment.severity,
            floor=computed.band.value,
            note="the model proposed a severity below the deterministic floor",
        )

    if assessment is not None:
        title = assessment.title.strip()[:200] or "Phishing assessment"
        description = assessment.explanation.strip()
        recommendation = assessment.recommendation.strip() or None
        confidence = CONFIDENCE_VALUES[assessment.confidence]
        verdict = assessment.verdict.value
    else:
        # No indicators fired, so no model was called. Still a finding: "analysed and
        # nothing found" has to stay distinguishable from "never analysed", which is what
        # a null verdict on the intake row means.
        title = "No phishing indicators found"
        description = (
            "This message was analysed by the phishing rule engine and no indicator "
            "fired. Authentication results, sender identity, links, attachments and "
            "message content were all checked."
        )
        recommendation = None
        confidence = CONFIDENCE_VALUES[ConfidenceBand.high]
        verdict = "clean"

    evidence: dict[str, Any] = {
        "verdict": verdict,
        "rule_engine": {
            "score": computed.value,
            "severity_floor": computed.band.value,
            "features": computed.features,
        },
        "indicators": [indicator.for_evidence() for indicator in ordered],
        "note": (
            "Indicator facts and excerpts are untrusted data taken from the submitted "
            "message. Render as text, never as markup."
        ),
    }
    if reconciliation is not None:
        evidence["ranking"] = {
            "model_ranked_ids": list(reconciliation.named_ids),
            "unknown_ids_dropped": list(reconciliation.unknown_ids),
            "duplicate_ids": list(reconciliation.duplicate_ids),
        }
    if assessment is not None:
        evidence["model"] = {
            "severity": assessment.severity,
            "confidence_band": assessment.confidence.value,
            "injection_signal": assessment.injection.signal.value,
            "injection_note": assessment.injection.note,
            "severity_floor_enforced": undercut,
        }
    if state.get("overflow_ids"):
        # Named rather than hidden: the analysis was capped, and an analyst should know
        # that instead of reading a partial result as a complete one.
        evidence["capped"] = {
            "dropped_indicator_count": len(state["overflow_ids"]),
            "dropped_indicator_ids": list(state["overflow_ids"]),
            "note": (
                "The weakest indicators beyond the configured cap were excluded from the "
                "model's input. They are listed here for completeness."
            ),
        }
    if state.get("enrichment"):
        evidence["enrichment"] = state["enrichment"]
    if message.body_text:
        evidence["body_excerpt"] = message.body_text[:BODY_EXCERPT_CHARS]

    return FindingCreate(
        agent=AgentKind.phishing,
        finding_type=finding_type,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        source=state["source"],
        asset=asset,
        evidence=evidence,
        recommendation=recommendation,
        detected_at=detected_at,
    )


def _injection_finding(
    *,
    state: PhishingState,
    ordered: list[Indicator],
    asset: str | None,
    detected_at: datetime,
) -> FindingCreate | None:
    """A separate finding when the content was aimed at the analyser.

    Raised when **either** detector fires: the deterministic rule, or the model's own
    report. Two independent signals, either sufficient - a crafted message that evades
    the patterns may still be noticed by the model, and a model that has been
    successfully steered is exactly the one that will report ``none``.
    """
    rule_fired = injection_rules.fired(ordered)
    assessment = state.get("assessment")
    model_signal = assessment.injection.signal if assessment else InjectionSignal.none
    model_fired = model_signal is not InjectionSignal.none

    if not (rule_fired or model_fired):
        return None

    detectors: list[str] = []
    if rule_fired:
        detectors.append("deterministic pattern rules")
    if model_fired:
        detectors.append(f"the model's own report ({model_signal.value})")

    return FindingCreate(
        agent=AgentKind.phishing,
        finding_type=FindingType.prompt_injection_attempt,
        title="Submitted message contains content aimed at the analysis system",
        description=(
            "This message contains text addressed to the automated system analysing it "
            "rather than to its recipient - for example instructions to ignore prior "
            "directions, to report the message as safe, or to reveal configuration. "
            f"Detected by {' and '.join(detectors)}. The content was treated as data "
            "throughout and never followed, and the phishing assessment alongside this "
            "finding was completed normally."
        ),
        severity=Severity.high,
        confidence=CONFIDENCE_VALUES[ConfidenceBand.high],
        source=state["source"],
        asset=asset,
        evidence={
            "detected_by": detectors,
            "rule_detector_fired": rule_fired,
            "model_detector_signal": model_signal.value,
            "model_note": assessment.injection.note if assessment else "",
            "indicators": [
                indicator.for_evidence()
                for indicator in ordered
                if indicator.category is IndicatorCategory.injection
            ],
            "note": (
                "Excerpts are untrusted data taken from the submitted message. Render as "
                "text, never as markup."
            ),
        },
        recommendation=(
            "Treat the sender as hostile and specifically targeting automated triage. "
            "Preserve the message for review, and check whether other messages from the "
            "same sender reached analysts."
        ),
        detected_at=detected_at,
    )
