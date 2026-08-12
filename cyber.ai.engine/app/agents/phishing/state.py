"""Graph state for the phishing detection agent."""

from __future__ import annotations

from typing import Any, NotRequired

from cyber_contracts import EnrichmentPolicy, NormalizedMessage

from app.agents.common.state import AgentState
from app.agents.phishing.assessment_schema import PhishingAssessment
from app.agents.phishing.indicators import Indicator
from app.agents.phishing.reconcile import Reconciliation
from app.agents.phishing.scoring import Score


class PhishingState(AgentState):
    """Phishing-specific working state, written node by node."""

    message: NotRequired[NormalizedMessage]
    policy: NotRequired[EnrichmentPolicy]
    indicators: NotRequired[list[Indicator]]
    overflow_ids: NotRequired[list[str]]
    enrichment: NotRequired[dict[str, Any]]
    score: NotRequired[Score]
    assessment: NotRequired[PhishingAssessment]
    reconciliation: NotRequired[Reconciliation]


def initial_phishing_state(
    *,
    message: NormalizedMessage,
    source: str,
    asset: str | None = None,
    policy: EnrichmentPolicy | None = None,
    context: dict[str, Any] | None = None,
) -> PhishingState:
    """Build a fully populated starting state.

    ``raw_input`` is set to a short provenance line - "email, 2 links, 1 attachment" -
    and **not** to the message body. The backend already parsed the artifact, so the
    ai.engine never needs the original bytes, and the body reaches a prompt only as the
    bounded excerpt ``prompt.build_assess_messages`` fences.

    That is deliberate and easy to undo by accident. Putting the body here would send it
    into the shared ``AgentState`` field that other code logs and previews, quietly
    widening the injection surface. This docstring exists so nobody "fixes" the empty
    look of it.
    """
    descriptor = (
        f"{message.format.value}, {message.link_count} link(s), "
        f"{message.attachment_count} attachment(s)"
    )
    return PhishingState(
        source=source,
        asset=asset,
        raw_input=descriptor,
        context=context or {},
        normalized={},
        messages=[],
        findings=[],
        message=message,
        policy=policy or EnrichmentPolicy(),
        indicators=[],
        overflow_ids=[],
        enrichment={},
    )
