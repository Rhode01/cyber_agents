"""Tools for the phishing detection agent. Declared, not yet bound to the model."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool


@tool
def check_email_authentication(message_id: str) -> dict[str, Any]:
    """Return SPF, DKIM, and DMARC results and alignment for a stored message."""
    # TODO(phase-2): resolve through the backend, which stores ingested messages.
    return {"message_id": message_id, "status": "not-implemented", "source": "phase-1-stub"}


@tool
def check_domain_reputation(domain: str) -> dict[str, Any]:
    """Return registration age, reputation score, and lookalike matches for a domain."""
    # TODO(phase-2): resolve through the backend's threat-intel integration.
    return {"domain": domain, "status": "not-implemented", "source": "phase-1-stub"}


TOOLS = [check_email_authentication, check_domain_reputation]
