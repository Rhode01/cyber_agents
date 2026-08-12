"""Node functions for the network traffic analysis agent.

Flow: scan → normalize → detect → reason → emit_findings

``scan`` takes a live ``ss`` TCP snapshot when no telemetry is provided.
``normalize`` uses Zeek/Suricata parsers (or the ``ss`` snapshot) to extract
standard metric fields.
``detect`` applies deterministic anomaly rules (DNS floods, port scans).
``reason`` feeds the metrics, alerts, and anomalies to the LLM.
``emit_findings`` creates contract-shaped findings.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from cyber_contracts import AgentKind, FindingCreate, FindingType, Severity
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from app.agents.common.findings import resolve_finding_type, resolve_severity
from app.agents.common.placeholder import placeholder_finding
from app.agents.common.untrusted import wrap_untrusted
from app.agents.network.prompt import SYSTEM_PROMPT
from app.agents.network.state import NetworkState
from app.agents.network.tools import capture_traffic_snapshot
from app.core.logging import get_logger
from app.llm.factory import (
    LlmNotConfiguredError,
    extract_message_text,
    require_configured_chat_model,
)
from app.parsers import ParseError, suricata, zeek

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

async def scan(state: NetworkState) -> dict[str, Any]:
    """Take a live TCP snapshot against ``asset`` when no telemetry is provided."""
    if state.get("raw_input", "").strip():
        return {"scan_info": {"status": "provided", "tool": state.get("source", "")}}

    target = (state.get("asset") or "").strip()
    result = await capture_traffic_snapshot(target)
    logger.info(
        "network.scan",
        target=target or "(this host)",
        ok=result["ok"],
        tool=result["tool"],
        length=len(result["output"]),
    )
    return {
        "raw_input": result.get("output", ""),
        "source": result.get("tool", "ss"),
        "scan_info": result,
    }


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------

async def normalize(state: NetworkState) -> dict[str, Any]:
    """Parse flow records and compute baseline metrics."""
    raw = state["raw_input"]
    source = state["source"].lower()
    logger.info("network.normalize", source=source, length=len(raw))

    metrics: dict[str, Any] = {
        "packets_total": 0,
        "bytes_total": 0,
        "connections_total": 0,
        "dns_queries_total": 0,
        "syn_total": 0,
        "conn_failed": 0,
        "top_talkers": [],
        "top_ports": [],
        "top_domains": [],
    }

    parsed_data: list[Any] = []
    parsed_flag = False
    records: list[Any] = []

    try:
        if source == "zeek-conn":
            records = zeek.parse_conn(raw)
            parsed_flag = True
            metrics["connections_total"] = len(records)
            src_counts: dict[str, int] = defaultdict(int)
            port_counts: dict[int, int] = defaultdict(int)

            for r in records:
                metrics["bytes_total"] += r.orig_bytes + r.resp_bytes
                metrics["packets_total"] += r.orig_pkts + r.resp_pkts
                if r.conn_state in ("S0", "REJ", "RSTOS0"):
                    metrics["conn_failed"] += 1
                if "S" in r.conn_state:  # crude SYN estimation
                    metrics["syn_total"] += 1
                src_counts[r.orig_h] += 1
                port_counts[r.resp_p] += 1

            metrics["top_talkers"] = sorted(
                src_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            metrics["top_ports"] = sorted(
                port_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            parsed_data = records

        elif source == "zeek-dns":
            records = zeek.parse_dns(raw)
            parsed_flag = True
            metrics["dns_queries_total"] = len(records)
            domain_counts: dict[str, int] = defaultdict(int)
            src_counts = defaultdict(int)

            for dns_rec in records:
                domain_counts[dns_rec.query] += 1
                src_counts[dns_rec.orig_h] += 1

            metrics["top_domains"] = sorted(
                domain_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            metrics["top_talkers"] = sorted(
                src_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            parsed_data = records

        elif source == "suricata":
            alerts = suricata.parse(raw)
            parsed_flag = True
            parsed_data = alerts

        elif source == "ss":
            # Live snapshot produced by the scan node. The report carries a
            # machine-parseable METRICS block followed by raw ss output.
            parsed_flag = True
            for line in raw.splitlines():
                if line.startswith("METRICS "):
                    _, key_value = line.split(" ", 1)
                    key, _, value = key_value.partition("=")
                    if key in (
                        "connections_total",
                        "established",
                        "listening",
                        "syn_sent",
                        "syn_recv",
                        "close_wait",
                    ):
                        metrics[key] = int(value)
                    elif key == "target":
                        metrics["target"] = value
                    elif key in ("top_talkers", "top_local_ports"):
                        metrics[key] = value

    except ParseError as exc:
        logger.warning("network.normalize.parse_failed", source=source, error=str(exc))

    # Assume traffic represents a 60-second window if no timestamps allow precise calculation
    window = 60
    if parsed_data and hasattr(parsed_data[0], "ts") and hasattr(parsed_data[-1], "ts"):
        window = max(1, int(parsed_data[-1].ts - parsed_data[0].ts))

    return {
        "normalized": {"source": source, "byte_length": len(raw), "parsed": parsed_flag},
        "metrics": metrics,
        "traffic_window_seconds": window,
        "parsed_data": parsed_data,  # temporary key passed to detect
    }


# ---------------------------------------------------------------------------
# detect
# ---------------------------------------------------------------------------

async def detect(state: NetworkState) -> dict[str, Any]:
    """Apply rule-based anomaly detection from the PDF."""
    source = state["source"].lower()
    metrics = state.get("metrics", {})
    window = state.get("traffic_window_seconds", 60)
    parsed_data: list[Any] = state.get("parsed_data", [])

    anomalies: list[dict[str, Any]] = []

    if source == "zeek-dns":
        # DNS flood detection
        qps = metrics.get("dns_queries_total", 0) / window
        nxdomains = sum(
            1
            for r in parsed_data
            if hasattr(r, "rcode_name") and r.rcode_name == "NXDOMAIN"
        )
        nx_ratio = nxdomains / metrics.get("dns_queries_total", 1)

        if qps > 100 or nx_ratio > 0.5:
            anomalies.append({
                "type": "dns_flood",
                "evidence": f"{qps:.1f} queries/sec, {nx_ratio:.1%} NXDOMAIN ratio",
            })

    elif source == "zeek-conn":
        # DDoS / SYN flood detection
        failed = metrics.get("conn_failed", 0)
        total = metrics.get("connections_total", 1)
        fail_ratio = failed / total

        if fail_ratio > 0.7 and total > 100:
            anomalies.append({
                "type": "syn_flood",
                "evidence": f"{fail_ratio:.1%} connection failure rate across {total} attempts",
            })

        # Port scan detection
        if parsed_data:
            from collections import defaultdict
            src_ports: dict[str, set[int]] = defaultdict(set)
            for r in parsed_data:
                if hasattr(r, "orig_h") and hasattr(r, "resp_p"):
                    src_ports[r.orig_h].add(r.resp_p)

            for src, ports in src_ports.items():
                if len(ports) > 50:
                    anomalies.append({
                        "type": "port_scan",
                        "evidence": f"Host {src} scanned {len(ports)} distinct ports",
                        "asset": src,
                    })

    elif source == "suricata":
        for a in parsed_data:
            if hasattr(a, "severity") and a.severity <= 2:
                anomalies.append({
                    "type": "ids_alert",
                    "evidence": f"[{a.category}] {a.signature}",
                    "asset": a.src_ip,
                })

    logger.info("network.detect", anomaly_count=len(anomalies))
    # Remove parsed_data from state as we don't need it passed to reason
    return {"anomalies": anomalies, "parsed_data": None}


# ---------------------------------------------------------------------------
# reason
# ---------------------------------------------------------------------------

async def reason(state: NetworkState) -> dict[str, Any]:
    """Assemble the prompt and call the LLM."""
    fenced = wrap_untrusted("network telemetry", state["raw_input"], max_chars=10_000)
    metrics = state.get("metrics", {})
    anomalies = state.get("anomalies", [])
    window = state.get("traffic_window_seconds", 60)

    context_lines = [f"Traffic window: {window} seconds"]
    if metrics:
        context_lines.append(f"Metrics: {json.dumps(metrics, indent=2)}")
    if anomalies:
        context_lines.append(f"Detections: {json.dumps(anomalies, indent=2)}")

    context_block = "\n".join(context_lines)
    human_content = f"{context_block}\n\n{fenced}" if context_block else fenced

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human_content)]
    raw_findings = []

    try:
        context = state.get("context", {})
        model = require_configured_chat_model(context=context)
        response: AIMessage = await model.ainvoke(messages)
        content = extract_message_text(response).strip()

        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]

        data = json.loads(content)
        raw_findings = data.get("findings", [])
        logger.info("network.reason", count=len(raw_findings), llm_invoked=True)
    except LlmNotConfiguredError:
        logger.warning("network.reason.no_llm", llm_invoked=False)
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.warning("network.reason.parse_failed", error=str(exc))
    except Exception as exc:
        logger.warning("network.reason.llm_error", error=str(exc), llm_invoked=False)

    return {"messages": messages, "raw_findings": raw_findings}


# ---------------------------------------------------------------------------
# emit_findings
# ---------------------------------------------------------------------------

async def emit_findings(state: NetworkState) -> dict[str, Any]:
    """Produce contract-shaped findings."""
    source = state["source"]
    asset = state["asset"]
    raw_findings = state.get("raw_findings", [])
    anomalies = state.get("anomalies", [])

    if not raw_findings and not anomalies:
        finding = placeholder_finding(
            agent=AgentKind.network,
            source=source,
            asset=asset,
            raw_input=state["raw_input"],
            summary="Telemetry analysed. No significant anomalies or LLM findings.",
        )
        return {"findings": [finding]}

    from datetime import UTC, datetime
    findings: list[FindingCreate] = []

    if raw_findings:
        for raw in raw_findings:
            sev_str = str(raw.get("severity", "info")).lower()
            severity = resolve_severity(sev_str, default=Severity.info)
            confidence = float(raw.get("confidence", 0.8))

            findings.append(FindingCreate(
                agent=AgentKind.network,
                finding_type=resolve_finding_type(raw, FindingType.informational),
                title=str(raw.get("title", "Network anomaly"))[:200],
                description=str(raw.get("description", "")),
                severity=severity,
                confidence=confidence,
                source=source,
                asset=raw.get("affected_asset") or asset,
                evidence={
                    "evidence_summary": raw.get("evidence_summary", ""),
                    "metrics": state.get("metrics", {}),
                },
                recommendation=raw.get("recommendation"),
                raw_reference=None,
                detected_at=datetime.now(UTC),
            ))
    elif anomalies:
        findings.append(FindingCreate(
            agent=AgentKind.network,
            finding_type=FindingType.informational,
            title=f"Network anomaly: {len(anomalies)} heuristic rule(s) fired",
            description="Deterministic rules identified abnormal traffic patterns.",
            severity=Severity.medium,
            confidence=0.8,
            source=source,
            asset=asset,
            evidence={"anomalies": anomalies, "llm_available": False},
            recommendation="Review traffic metrics manually.",
            raw_reference=None,
            detected_at=datetime.now(UTC),
        ))

    logger.info("network.emit_findings", count=len(findings))
    return {"findings": findings}
