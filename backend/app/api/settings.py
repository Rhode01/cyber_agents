"""Settings endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.api.deps import SessionDep
from app.core.security import CurrentPrincipal
from app.models.setting import Setting as SettingModel

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingRead(BaseModel):
    key: str
    value: str
    description: str | None = None


class SettingUpdate(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    value: str


@router.get("", response_model=list[SettingRead], summary="List all settings")
async def get_settings(session: SessionDep, principal: CurrentPrincipal) -> list[SettingRead]:
    """Retrieve all configuration keys."""
    del principal
    stmt = select(SettingModel).order_by(SettingModel.key)
    rows = (await session.execute(stmt)).scalars().all()
    return [SettingRead(key=row.key, value=row.value, description=row.description) for row in rows]


@router.post("", response_model=SettingRead, summary="Upsert a setting")
async def update_setting(
    payload: SettingUpdate, session: SessionDep, principal: CurrentPrincipal
) -> SettingRead:
    """Insert or update a configuration key."""
    del principal

    stmt = insert(SettingModel).values(key=payload.key, value=payload.value)
    stmt = stmt.on_conflict_do_update(
        index_elements=["key"], set_={"value": stmt.excluded.value}
    )
    await session.execute(stmt)
    await session.commit()
    
    # Return the newly updated setting
    row = await session.get(SettingModel, payload.key)
    if not row:
        raise RuntimeError("Failed to read setting after upsert")
        
    return SettingRead(key=row.key, value=row.value, description=row.description)
