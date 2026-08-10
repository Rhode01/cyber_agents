"""Generic async CRUD base.

Endpoints should not build ``select()`` statements inline. Putting the query
layer here keeps the routers thin and gives every model the same paging, filter
and count semantics for free.

Two deliberate differences from the usual template:

* ``count`` uses ``SELECT count(*)`` rather than loading rows and measuring the
  list. On a findings table that grows to millions of rows the difference is a
  full table read versus an index-only scan.
* ``update`` takes the loaded object and applies only the fields the caller
  actually set (``exclude_unset``), so a partial PATCH cannot silently blank a
  column it never mentioned.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.db.base import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """Create, read, update and delete for one SQLAlchemy model."""

    def __init__(self, model: type[ModelType]) -> None:
        self.model = model

    async def get(self, db: AsyncSession, id: Any) -> ModelType | None:  # noqa: A002
        """Return one row by primary key, or None."""
        return await db.get(self.model, id)

    async def get_multi(
        self,
        db: AsyncSession,
        *,
        filters: list[ColumnElement[bool]] | None = None,
        order_by: Any = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ModelType]:
        """Return a page of rows matching ``filters``."""
        statement = select(self.model).where(*(filters or []))
        if order_by is not None:
            statement = statement.order_by(order_by)
        statement = statement.limit(limit).offset(offset)
        rows = (await db.execute(statement)).scalars().all()
        return list(rows)

    async def count(
        self, db: AsyncSession, *, filters: list[ColumnElement[bool]] | None = None
    ) -> int:
        """Count rows matching ``filters`` without loading them."""
        statement = select(func.count()).select_from(self.model).where(*(filters or []))
        return int((await db.execute(statement)).scalar_one())

    async def create(self, db: AsyncSession, *, obj_in: CreateSchemaType) -> ModelType:
        """Insert one row built from a Pydantic model."""
        row = self.model(**obj_in.model_dump())
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return row

    async def create_many(self, db: AsyncSession, *, rows: list[ModelType]) -> list[ModelType]:
        """Insert many already-built rows in one transaction."""
        if not rows:
            return []
        db.add_all(rows)
        await db.commit()
        for row in rows:
            await db.refresh(row)
        return rows

    async def update(
        self,
        db: AsyncSession,
        *,
        db_obj: ModelType,
        obj_in: UpdateSchemaType | dict[str, Any],
    ) -> ModelType:
        """Apply only the fields the caller set, then commit."""
        data = obj_in if isinstance(obj_in, dict) else obj_in.model_dump(exclude_unset=True)
        for field, value in data.items():
            if hasattr(db_obj, field):
                setattr(db_obj, field, value)
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def delete(self, db: AsyncSession, *, id: Any) -> ModelType | None:  # noqa: A002
        """Delete one row by primary key and return what was removed."""
        row = await self.get(db, id)
        if row is not None:
            await db.delete(row)
            await db.commit()
        return row
