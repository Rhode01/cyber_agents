"""Router for the phishing detection agent.

Two entry paths, mirroring the vulnerability agent:

* ``POST /analyze`` takes a raw artifact through the generic ``AnalyzeRequest``. Kept for
  the callers that still use it; it returns a finding saying the path is superseded
  rather than pretending to analyse.
* ``POST /assess`` takes a message the backend already parsed. This is the real path -
  uploaded ``.eml`` files and submitted URLs come this way, because the backend owns
  parsing, so what crosses the wire is a ``NormalizedMessage`` rather than raw bytes.

The second exists because ``AnalyzeRequest`` forbids extra fields, so a request carrying a
parsed message cannot be squeezed into it. Sending one to ``/analyze`` answers 422, which
is what the message intake did until this route existed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from cyber_contracts import (
    AgentKind,
    FindingCreate,
    FindingType,
    PhishingAnalyzeRequest,
    Severity,
)
from fastapi import APIRouter, Depends

from app.agents.phishing.graph import GRAPH
from app.agents.phishing.state import initial_phishing_state
from app.core.logging import get_logger
from app.core.security import InternalKeyGuard
from app.schemas.requests import AnalyzeRequest, AnalyzeResponse

logger = get_logger(__name__)

AGENT = AgentKind.phishing

router = APIRouter(
    prefix=f"/agents/{AGENT.value}", tags=[AGENT.value], dependencies=[InternalKeyGuard]
)


def graph_config() -> dict[str, Any]:
    """Config passed into every graph run on this router.

    Empty in production, which is what makes the real assessor and the real scorer the
    default. A test overrides this dependency to inject a double - the seam reaches
    through HTTP that way, without the router itself knowing anything about testing.
    """
    return {}


GraphConfig = Annotated[dict[str, Any], Depends(graph_config)]


@router.post(
    "/assess",
    response_model=AnalyzeResponse,
    summary="Assess a message the backend has already parsed",
)
async def assess(payload: PhishingAnalyzeRequest, config: GraphConfig) -> AnalyzeResponse:
    """Assess a ``NormalizedMessage`` for phishing.

    Almost every string inside ``payload.message`` is untrusted - a phishing email is a
    document written to manipulate whoever reads it, and downstream of here the reader is
    a language model. The rule engine treats it as data throughout, and it reaches a
    prompt only inside the fence, once.
    """
    logger.info(
        "router.assess",
        agent=AGENT.value,
        source=payload.source,
        intake_id=str(payload.intake_id),
        format=payload.message.format.value,
        links=payload.message.link_count,
        attachments=payload.message.attachment_count,
        fetch_urls=payload.enrichment.fetch_urls,
    )

    state = initial_phishing_state(
        message=payload.message,
        source=payload.source,
        asset=payload.asset,
        policy=payload.enrichment,
        context={**payload.context, "intake_id": str(payload.intake_id)},
    )
    result = await GRAPH.ainvoke(state, config=config)

    return AnalyzeResponse(agent=AGENT, findings=result["findings"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Superseded by /assess - kept so existing callers get a clear answer",
)
async def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Report that this path no longer performs analysis.

    The agent now works from a parsed ``NormalizedMessage``, which this request shape
    cannot carry. Returning an informational finding rather than a 404 or a silent empty
    list: a caller wired to this route gets a visible, self-explaining answer instead of
    either an error with no guidance or a clean-looking result that was never assessed.
    """
    logger.info("router.analyze.superseded", agent=AGENT.value, source=payload.source)

    return AnalyzeResponse(
        agent=AGENT,
        findings=[
            FindingCreate(
                agent=AGENT,
                finding_type=FindingType.informational,
                title="Phishing analysis requires the /assess endpoint",
                description=(
                    "This request reached POST /agents/phishing/analyze, which no longer "
                    "performs analysis. The phishing agent works from a message the "
                    "backend has parsed, so submit the artifact to POST /messages (for an "
                    "email file) or POST /messages/url (for a URL) on the backend, which "
                    "parses it and calls POST /agents/phishing/assess. Nothing was "
                    "analysed for this request."
                ),
                severity=Severity.info,
                confidence=0.0,
                source=payload.source,
                asset=payload.asset,
                evidence={
                    "superseded_endpoint": "/agents/phishing/analyze",
                    "use_instead": "/agents/phishing/assess",
                    "backend_intake": ["POST /messages", "POST /messages/url"],
                },
                recommendation=(
                    "Submit the message through the backend's /messages intake, which "
                    "parses it and calls the assess endpoint."
                ),
                detected_at=datetime.now(UTC),
            )
        ],
    )
