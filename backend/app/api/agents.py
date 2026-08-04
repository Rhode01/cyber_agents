"""Agent orchestration endpoints.

One route covers all four agents. The backend decides whether to call the
ai.engine inline or hand the work to the arq worker; the ai.engine itself never
knows the difference and never touches the database either way.
"""

from __future__ import annotations

from cyberagents_contracts import AgentKind
from fastapi import APIRouter, HTTPException, status

from app.api.deps import AiEngineDep, SessionDep, SettingsDep
from app.core.logging import get_logger
from app.core.security import CurrentPrincipal
from app.schemas.agents import AgentRunRequest, AgentRunResponse
from app.schemas.finding import FindingRead
from app.services.ai_engine_client import AiEngineError
from app.services.orchestration import run_agent
from app.worker.tasks import enqueue_agent_run

logger = get_logger(__name__)

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post(
    "/{agent}/run",
    response_model=AgentRunResponse,
    summary="Run one detection agent over one artifact",
    responses={status.HTTP_502_BAD_GATEWAY: {"description": "The ai.engine did not answer."}},
)
async def run(
    agent: AgentKind,
    payload: AgentRunRequest,
    session: SessionDep,
    client: AiEngineDep,
    settings: SettingsDep,
    principal: CurrentPrincipal,
) -> AgentRunResponse:
    """Send an artifact to one ai.engine agent and persist what comes back."""
    del principal

    if payload.background:
        job_id = await enqueue_agent_run(settings.redis_url, agent, payload)
        return AgentRunResponse(
            agent=agent,
            mode="background",
            persisted=payload.persist,
            job_id=job_id,
        )

    try:
        rows = await run_agent(session, client, agent, payload)
    except AiEngineError as err:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(err)) from err

    return AgentRunResponse(
        agent=agent,
        mode="inline",
        persisted=payload.persist,
        findings=[FindingRead.model_validate(row) for row in rows],
    )
