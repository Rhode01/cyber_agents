"""Shared contracts between the backend and the ai.engine.

Import from here rather than from submodules so the public surface stays small.

Bump ``__version__`` on any field change, then run ``make lock`` so both
consumers re-resolve the path dependency.
"""

from cyberagents_contracts.analyze import VulnerabilityAnalyzeRequest
from cyberagents_contracts.discovery import DiscoveryReport, InterfaceInfo, ServicePort, WebHost
from cyberagents_contracts.finding import (
    SEVERITY_ORDER,
    AgentKind,
    Finding,
    FindingBatch,
    FindingCreate,
    FindingStatus,
    FindingType,
    Severity,
)
from cyberagents_contracts.scan import (
    NormalizedScan,
    ScanFormat,
    ScanHost,
    ScanPort,
    ScanStatus,
)

__all__ = [
    "SEVERITY_ORDER",
    "AgentKind",
    "DiscoveryReport",
    "Finding",
    "FindingBatch",
    "FindingCreate",
    "FindingStatus",
    "FindingType",
    "InterfaceInfo",
    "NormalizedScan",
    "ScanFormat",
    "ScanHost",
    "ScanPort",
    "ScanStatus",
    "ServicePort",
    "Severity",
    "VulnerabilityAnalyzeRequest",
    "WebHost",
]

__version__ = "0.5.0"
