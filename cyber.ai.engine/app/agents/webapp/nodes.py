"""Node functions for the web application security agent.

Flow: scan → normalize → categorize → reason → emit_findings

``scan`` launches a Nuclei scan against the target URL when no report is given.
``normalize`` uses ZAP or Nuclei parsers.
``categorize`` maps alerts to OWASP Top 10:2025 categories based on rules.
``reason`` calls LLM to filter false positives and enrich findings.
``emit_findings`` creates contract-shaped findings.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from cyber_contracts import AgentKind, FindingCreate, FindingType, Severity
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from app.agents.common.findings import resolve_finding_type
from app.agents.common.placeholder import placeholder_finding
from app.agents.common.untrusted import wrap_untrusted
from app.agents.webapp.prompt import SYSTEM_PROMPT
from app.agents.webapp.state import WebappState
from app.agents.webapp.tools import run_nuclei_scan
from app.core.logging import get_logger
from app.llm.factory import (
    LlmNotConfiguredError,
    extract_message_text,
    require_configured_chat_model,
)
from app.parsers import ParseError, nuclei, zap

logger = get_logger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "informational": Severity.info,
}


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

async def scan(state: WebappState) -> dict[str, Any]:
    """Launch a Nuclei scan against the target URL when no report is provided."""
    if state.get("raw_input", "").strip():
        return {"scan_info": {"status": "provided", "tool": state.get("source", "")}}

    target = (state.get("asset") or "").strip()
    if not target:
        return {"scan_info": {"status": "no-target", "tool": state.get("source", "")}}

    result = await run_nuclei_scan(target)
    normalized_url = result["meta"].get("target_url") or target
    logger.info(
        "webapp.scan",
        target=target,
        ok=result["ok"],
        tool=result["tool"],
        length=len(result["output"]),
    )
    return {
        "raw_input": result.get("output", ""),
        "source": result.get("tool", "nuclei"),
        "asset": normalized_url,
        "scan_info": result,
    }


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------

async def normalize(state: WebappState) -> dict[str, Any]:
    """Parse ZAP or Nuclei output."""
    raw = state["raw_input"]
    source = state["source"].lower()
    logger.info("webapp.normalize", source=source, length=len(raw))

    parsed_alerts: list[dict[str, Any]] = []
    target_url = state["asset"]
    parsed_flag = False

    try:
        if source in ("zap", "zap-json", "zap-xml"):
            report = zap.parse(raw)
            parsed_flag = True
            if not target_url and report.site:
                target_url = report.site

            for alert in report.alerts:
                parsed_alerts.append({
                    "name": alert.name,
                    "risk": alert.risk,
                    "confidence": alert.confidence,
                    "description": alert.description,
                    "owasp_id": alert.owasp_id,
                    "cwe_id": alert.cwe_id,
                    "instances": [
                        {
                            "uri": inst.uri,
                            "method": inst.method,
                            "param": inst.param,
                            "evidence": inst.evidence,
                        }
                        for inst in alert.instances
                    ]
                })

        elif source in ("nuclei", "nuclei-json"):
            findings = nuclei.parse(raw)
            parsed_flag = True
            if not target_url and findings:
                target_url = findings[0].host

            for finding in findings:
                parsed_alerts.append({
                    "name": finding.template_name,
                    "risk": finding.severity,
                    "confidence": "High",  # Nuclei templates are usually deterministic
                    "description": finding.description,
                    "owasp_id": "",  # Will be enriched by categorize
                    "cwe_id": "",
                    "tags": finding.tags,
                    "instances": [
                        {
                            "uri": finding.matched_at,
                            "method": "GET",  # Default if unknown
                            "evidence": finding.matched_line,
                        }
                    ]
                })

    except ParseError as exc:
        logger.warning("webapp.normalize.parse_failed", source=source, error=str(exc))

    return {
        "normalized": {"source": source, "byte_length": len(raw), "parsed": parsed_flag},
        "target_url": target_url,
        "parsed_alerts": parsed_alerts,
    }


# ---------------------------------------------------------------------------
# categorize
# ---------------------------------------------------------------------------

async def categorize(state: WebappState) -> dict[str, Any]:
    """Map parsed alerts to OWASP Top 10 categories."""
    alerts = state.get("parsed_alerts", [])
    owasp_categories: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # Basic heuristic mapping if OWASP ID is missing
    tag_mapping = {
        "xss": "A03:2021",  # Injection
        "sqli": "A03:2021", # Injection
        "injection": "A03:2021",
        "auth": "A07:2021", # Identification and Authentication Failures
        "default-login": "A07:2021",
        "lfi": "A01:2021",  # Broken Access Control
        "rce": "A03:2021",  # Injection
        "misconfiguration": "A05:2021", # Security Misconfiguration
        "ssl": "A02:2021",  # Cryptographic Failures
        "tls": "A02:2021",
    }

    for alert in alerts:
        owasp_id = alert.get("owasp_id") or ""
        
        # If no OWASP ID, try to guess from tags (Nuclei) or CWE (ZAP)
        if not owasp_id:
            tags = alert.get("tags", [])
            for tag in tags:
                if tag.lower() in tag_mapping:
                    owasp_id = tag_mapping[tag.lower()]
                    alert["owasp_id"] = owasp_id
                    break

            if not owasp_id and alert.get("cwe_id"):
                cwe = alert["cwe_id"]
                if cwe in ("79", "89", "94", "78"):
                    owasp_id = "A03:2021"
                elif cwe in ("287", "300"):
                    owasp_id = "A07:2021"
                elif cwe in ("16", "200"):
                    owasp_id = "A05:2021"

        if not owasp_id:
            owasp_id = "Uncategorized"

        owasp_categories[owasp_id].append(alert)

    logger.info("webapp.categorize", mapped_categories=len(owasp_categories))
    return {"owasp_categories": dict(owasp_categories), "parsed_alerts": alerts}


# ---------------------------------------------------------------------------
# reason
# ---------------------------------------------------------------------------

async def reason(state: WebappState) -> dict[str, Any]:
    """Call the LLM with categorized alerts."""
    fenced = wrap_untrusted("web scanner report", state["raw_input"], max_chars=10_000)
    categories = state.get("owasp_categories", {})
    
    context_lines = []
    if categories:
        context_lines.append(f"Parsed and categorized alerts:\n{json.dumps(categories, indent=2)}")

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
        logger.info("webapp.reason", count=len(raw_findings), llm_invoked=True)
    except LlmNotConfiguredError:
        logger.warning("webapp.reason.no_llm", llm_invoked=False)
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.warning("webapp.reason.parse_failed", error=str(exc))
    except Exception as exc:
        logger.warning("webapp.reason.llm_error", error=str(exc), llm_invoked=False)

    return {"messages": messages, "raw_findings": raw_findings}


# ---------------------------------------------------------------------------
# emit_findings
# ---------------------------------------------------------------------------

async def emit_findings(state: WebappState) -> dict[str, Any]:
    """Produce contract-shaped findings."""
    source = state["source"]
    asset = state.get("target_url") or state["asset"]
    raw_findings = state.get("raw_findings", [])
    parsed_alerts = state.get("parsed_alerts", [])

    if not raw_findings and not parsed_alerts:
        finding = placeholder_finding(
            agent=AgentKind.webapp,
            source=source,
            asset=asset,
            raw_input=state["raw_input"],
            summary="Scanner report analysed. No significant findings or LLM available.",
        )
        return {"findings": [finding]}

    from datetime import UTC, datetime
    findings: list[FindingCreate] = []

    if raw_findings:
        for raw in raw_findings:
            sev_str = str(raw.get("severity", "info")).lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.info)
            confidence = float(raw.get("confidence", 0.8))

            findings.append(FindingCreate(
                agent=AgentKind.webapp,
                finding_type=resolve_finding_type(raw, FindingType.weak_configuration),
                title=str(raw.get("title", "Web application vulnerability"))[:200],
                description=str(raw.get("description", "")),
                severity=severity,
                confidence=confidence,
                source=source,
                asset=raw.get("affected_asset") or asset,
                evidence={
                    "owasp_category": raw.get("owasp_category", ""),
                    "evidence_summary": raw.get("evidence_summary", ""),
                },
                recommendation=raw.get("recommendation"),
                raw_reference=None,
                detected_at=datetime.now(UTC),
            ))
    elif parsed_alerts:
        for alert in parsed_alerts:
            sev_str = str(alert.get("risk", "info")).lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.info)
            
            findings.append(FindingCreate(
                agent=AgentKind.webapp,
                finding_type=resolve_finding_type(alert, FindingType.weak_configuration),
                title=f"Scanner alert: {alert.get('name')}",
                description=alert.get("description", ""),
                severity=severity,
                confidence=0.8,
                source=source,
                asset=asset,
                evidence={"alert_details": alert, "llm_available": False},
                recommendation="Review scanner output manually.",
                raw_reference=None,
                detected_at=datetime.now(UTC),
            ))

    logger.info("webapp.emit_findings", count=len(findings))
    return {"findings": findings}
