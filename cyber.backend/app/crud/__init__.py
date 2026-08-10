"""CRUD layer.

One module per model, each exposing a lower-case singleton so endpoints read as
``crud.finding.get_multi(...)``. Query construction lives here rather than in the
routers.
"""

from app.crud.crud_base import CRUDBase
from app.crud.crud_finding import DEDUPE_WINDOW, DedupeKey, dedupe_key, finding
from app.crud.crud_run import run
from app.crud.crud_scan import scan

__all__ = [
    "DEDUPE_WINDOW",
    "CRUDBase",
    "DedupeKey",
    "dedupe_key",
    "finding",
    "run",
    "scan",
]
