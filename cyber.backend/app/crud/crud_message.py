"""Message intake query layer."""

from __future__ import annotations

from typing import Any

from cyber_contracts import MessageStatus, MessageVerdict
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from app.crud.crud_base import CRUDBase
from app.models.message import Message
from app.schemas.message import MessageRead


class CRUDMessage(CRUDBase[Message, MessageRead, MessageRead]):
    """Messages, newest submission first."""

    @staticmethod
    def build_filters(
        *,
        status: MessageStatus | None = None,
        verdict: MessageVerdict | None = None,
    ) -> list[ColumnElement[bool]]:
        filters: list[ColumnElement[bool]] = []
        if status is not None:
            filters.append(Message.status == status.value)
        if verdict is not None:
            filters.append(Message.verdict == verdict.value)
        return filters

    @staticmethod
    def newest_first() -> UnaryExpression[Any]:
        return Message.created_at.desc()


message = CRUDMessage(Message)
