"""Pipeline run query layer."""

from __future__ import annotations

from typing import Any

from sqlalchemy.sql.elements import UnaryExpression

from app.crud.crud_base import CRUDBase
from app.models.run import Run
from app.schemas.run import RunCreate, RunUpdate


class CRUDRun(CRUDBase[Run, RunCreate, RunUpdate]):
    """Runs, newest first."""

    @staticmethod
    def newest_first() -> UnaryExpression[Any]:
        return Run.created_at.desc()


run = CRUDRun(Run)
