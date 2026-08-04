"""Shared contracts between the backend and the ai.engine.

Import from here rather than from submodules so the public surface stays small.
"""

from cyberagents_contracts.finding import (
    SEVERITY_ORDER,
    AgentKind,
    Finding,
    FindingBatch,
    FindingCreate,
    Severity,
)

__all__ = [
    "SEVERITY_ORDER",
    "AgentKind",
    "Finding",
    "FindingBatch",
    "FindingCreate",
    "Severity",
]

__version__ = "0.1.0"
