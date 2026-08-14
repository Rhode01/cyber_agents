"""Shared contracts between the backend and the ai.engine.

Import from here rather than from submodules so the public surface stays small.

Bump ``__version__`` on any field change, then run ``make lock`` so both
consumers re-resolve the path dependency.
"""

from cyber_contracts.analyze import (
    EnrichmentPolicy,
    PhishingAnalyzeRequest,
    VulnerabilityAnalyzeRequest,
)
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
from cyber_contracts.message import (
    AuthResults,
    EmailAddress,
    EmailAttachment,
    EmailLink,
    MessageFormat,
    MessageStatus,
    MessageVerdict,
    NormalizedMessage,
)
from cyber_contracts.scan import (
    NormalizedScan,
    ScanFormat,
    ScanHost,
    ScanPort,
    ScanStatus,
)
from cyber_contracts.scope import (
    FORBIDDEN_SCOPE_NETWORKS,
    MAX_SCOPE_ADDRESSES,
    ScanScopeCreate,
    ScanScopeEntry,
    ScanScopeList,
    ScanScopeNetworks,
    normalize_scope_target,
)
from cyber_contracts.security import INTERNAL_KEY_HEADER, matches_internal_key
from cyber_contracts.verification import (
    HostCoverage,
    VerificationReport,
    VerificationRequest,
    VerificationTarget,
)

__all__ = [
    "FORBIDDEN_SCOPE_NETWORKS",
    "INTERNAL_KEY_HEADER",
    "MAX_SCOPE_ADDRESSES",
    "SEVERITY_ORDER",
    "AgentKind",
    "AuthResults",
    "DiscoveryReport",
    "EmailAddress",
    "EmailAttachment",
    "EmailLink",
    "EnrichmentPolicy",
    "Finding",
    "FindingBatch",
    "FindingCreate",
    "FindingStatus",
    "FindingType",
    "HostCoverage",
    "InterfaceInfo",
    "MessageFormat",
    "MessageStatus",
    "MessageVerdict",
    "NormalizedMessage",
    "NormalizedScan",
    "PhishingAnalyzeRequest",
    "ScanFormat",
    "ScanHost",
    "ScanPort",
    "ScanScopeCreate",
    "ScanScopeEntry",
    "ScanScopeList",
    "ScanScopeNetworks",
    "ScanStatus",
    "ServicePort",
    "Severity",
    "VerificationReport",
    "VerificationRequest",
    "VerificationTarget",
    "VulnerabilityAnalyzeRequest",
    "WebHost",
    "matches_internal_key",
    "normalize_scope_target",
]

__version__ = "0.9.0"
