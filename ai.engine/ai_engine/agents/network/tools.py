"""Tools for the network traffic analysis agent. Declared, not yet bound to the model."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool


@tool
def get_traffic_baseline(asset: str, window: str) -> dict[str, Any]:
    """Return the established traffic baseline for an asset over a time window."""
    # TODO(phase-2): resolve through the backend, which stores the baselines.
    return {"asset": asset, "window": window, "status": "not-implemented"}


@tool
def check_ip_reputation(ip_address: str) -> dict[str, Any]:
    """Return reputation, ASN, and known-C2 status for an IP address."""
    # TODO(phase-2): resolve through the backend's threat-intel integration.
    return {"ip_address": ip_address, "status": "not-implemented"}


TOOLS = [get_traffic_baseline, check_ip_reputation]
