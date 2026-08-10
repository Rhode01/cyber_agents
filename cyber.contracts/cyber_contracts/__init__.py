"""Shared contracts between the backend and the ai.engine.

Import from here rather than from submodules so the public surface stays small.

Bump ``__version__`` on any field change, then run ``make lock`` so both
consumers re-resolve the path dependency.
"""

from cyber_contracts.analyze import VulnerabilityAnalyzeRequest
from cyber_contracts.discovery import DiscoveryReport, InterfaceInfo, ServicePort, WebHost
from cyber_contracts.finding import (
    SEVERITY_ORDER,
    AgentKind,
    Finding,
    FindingBatch,
    FindingCreate,
    FindingStatus,
    FindingType,
    Severity,
)
from cyber_contracts.scan import (
    NormalizedScan,
    ScanFormat,
    ScanHost,
    ScanPort,
    ScanStatus,
)
from cyber_contracts.security import INTERNAL_KEY_HEADER, matches_internal_key

__all__ = [
    "INTERNAL_KEY_HEADER",
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
    "matches_internal_key",
]

__version__ = "0.6.0"
