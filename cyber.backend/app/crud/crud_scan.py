"""Scan intake query layer."""

from __future__ import annotations

from cyber_contracts import ScanStatus
from sqlalchemy.sql.elements import ColumnElement

from app.crud.crud_base import CRUDBase
from app.models.scan import Scan
from app.schemas.scan import ScanRead


class CRUDScan(CRUDBase[Scan, ScanRead, ScanRead]):
    """Scans, newest upload first."""

    @staticmethod
    def build_filters(*, status: ScanStatus | None = None) -> list[ColumnElement[bool]]:
        filters: list[ColumnElement[bool]] = []
        if status is not None:
            filters.append(Scan.status == status.value)
        return filters

    @staticmethod
    def newest_first() -> ColumnElement[object]:
        return Scan.created_at.desc()


scan = CRUDScan(Scan)
