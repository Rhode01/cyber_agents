"""Suricata EVE JSON log parser.

Suricata writes one JSON object per line (NDJSON) to its ``eve.json`` file.
This parser focuses on ``event_type == "alert"`` records, which are the most
relevant for the network analysis agent.

Example::

    alerts = parse(raw_eve_json)
    for alert in alerts:
        print(alert.src_ip, alert.signature, alert.severity)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SuricataAlert:
    timestamp: str
    flow_id: int
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    signature: str
    signature_id: int
    category: str
    severity: int           # 1 (highest) - 4 (lowest)
    action: str             # allowed / blocked
    payload_printable: str  # "" if not present
    http_hostname: str      # "" if not HTTP
    http_url: str
    dns_query: str          # "" if not DNS
    extra: dict[str, Any] = field(default_factory=dict)


def parse(raw: str) -> list[SuricataAlert]:
    """Parse Suricata EVE JSON (NDJSON).

    Silently skips non-alert event types and malformed lines.
    Returns an empty list if no alert records are found.
    """
    alerts: list[SuricataAlert] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if record.get("event_type") != "alert":
            continue

        alert_block = record.get("alert", {})
        http_block = record.get("http", {})
        dns_block = record.get("dns", {})

        alerts.append(SuricataAlert(
            timestamp=record.get("timestamp", ""),
            flow_id=int(record.get("flow_id", 0)),
            src_ip=record.get("src_ip", ""),
            src_port=int(record.get("src_port", 0)),
            dest_ip=record.get("dest_ip", ""),
            dest_port=int(record.get("dest_port", 0)),
            proto=record.get("proto", ""),
            signature=alert_block.get("signature", ""),
            signature_id=int(alert_block.get("signature_id", 0)),
            category=alert_block.get("category", ""),
            severity=int(alert_block.get("severity", 3)),
            action=alert_block.get("action", "allowed"),
            payload_printable=record.get("payload_printable", ""),
            http_hostname=http_block.get("hostname", ""),
            http_url=http_block.get("url", ""),
            dns_query=(
                dns_block.get("query", {}).get("rrname", "")
                if isinstance(dns_block.get("query"), dict)
                else ""
            ),
            extra={k: v for k, v in record.items() if k not in (
                "event_type", "timestamp", "flow_id", "src_ip", "src_port",
                "dest_ip", "dest_port", "proto", "alert", "http", "dns",
                "payload_printable",
            )},
        ))

    return alerts
