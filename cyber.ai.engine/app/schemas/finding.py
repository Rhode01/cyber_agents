"""The Finding contract, as seen by the ai.engine.

Nothing is redefined here. The shape is imported from the shared
``cyber_contracts`` package - the same package the backend installs into
its own separate virtualenv - so the two services cannot drift apart.
"""

from __future__ import annotations

from cyber_contracts import (
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
