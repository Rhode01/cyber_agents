"""Settings configuration model."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Setting(Base):
    """A key-value configuration setting."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(
        sa.String(length=100), primary_key=True, doc="The configuration key (e.g. openai_api_key)"
    )
    value: Mapped[str] = mapped_column(
        sa.Text(), nullable=False, doc="The configuration value"
    )
    description: Mapped[str | None] = mapped_column(
        sa.Text(), nullable=True, doc="Optional description of what this setting does"
    )
