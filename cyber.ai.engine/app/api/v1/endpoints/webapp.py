"""Router for the web application security agent."""

from __future__ import annotations

from cyber_contracts import AgentKind
from fastapi import APIRouter

from app.agents.common.state import initial_state
from app.agents.webapp.graph import GRAPH
from app.core.logging import get_logger
from app.schemas.requests import AnalyzeRequest, AnalyzeResponse

logger = get_logger(__name__)

AGENT = AgentKind.webapp

router = APIRouter(prefix=f"/agents/{AGENT.value}", tags=[AGENT.value])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyse a web scanner report against the OWASP Top 10",
)
async def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Run the web application security graph over one scanner report.

    Phase 1 returns a placeholder finding: the graph runs, no model is called.
    """
    logger.info("router.analyze", agent=AGENT.value, source=payload.source)

    state = initial_state(
        source=payload.source,
        raw_input=payload.raw_input,
        asset=payload.asset,
        context=payload.context,
    )
    result = await GRAPH.ainvoke(state)

    return AnalyzeResponse(agent=AGENT, findings=result["findings"])
