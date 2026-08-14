"""Tool implementations exposed over MCP.

The MCP tool decorators live in ``app.server``; the work lives here, so each
piece is testable without an MCP session. Anything that runs a subprocess or
reaches the network belongs in this package.

``targets`` holds two policies that are exact inverses - what may be scanned, and what may
be fetched. They sit in one module on purpose; see its docstring.
"""

from app.tools.cve import CVE_ID_RE, CveLookup
from app.tools.dnsrecords import DNS_AVAILABLE, lookup_dns_records
from app.tools.exposure import classify_exposure
from app.tools.fetch import FetchOutcome, fetch_page
from app.tools.rdap import lookup_domain_age
from app.tools.scanning import duration_seconds, run_command, tool_result
from app.tools.scope import fetch_scope_networks
from app.tools.targets import (
    FetchDecision,
    TargetDecision,
    check_fetch_target,
    check_target,
    normalize_target,
    parse_networks,
)

__all__ = [
    "CVE_ID_RE",
    "DNS_AVAILABLE",
    "CveLookup",
    "FetchDecision",
    "FetchOutcome",
    "TargetDecision",
    "check_fetch_target",
    "check_target",
    "classify_exposure",
    "duration_seconds",
    "fetch_page",
    "fetch_scope_networks",
    "lookup_dns_records",
    "lookup_domain_age",
    "normalize_target",
    "parse_networks",
    "run_command",
    "tool_result",
]
