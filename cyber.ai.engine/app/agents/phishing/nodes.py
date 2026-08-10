"""Node functions for the phishing detection agent.

Flow: scan → normalize → rule_check → reason → emit_findings

``scan`` runs live DNS + HTTP checks against a URL/domain/email when no email
artifact is provided.
``normalize`` parses the MIME email (or the self-launched URL/DNS report).
``rule_check`` applies deterministic rules (SPF/DKIM failures, domain mismatches).
``reason`` calls the LLM with the rule hits and email content for a final verdict.
``emit_findings`` creates a FindingCreate based on the LLM verdict and rule hits.
"""

from __future__ import annotations

import json
from typing import Any

from cyber_contracts import AgentKind, FindingCreate, FindingType, Severity
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from app.agents.common.findings import resolve_finding_type
from app.agents.common.placeholder import placeholder_finding
from app.agents.common.targets import is_local_target
from app.agents.common.untrusted import wrap_untrusted
from app.agents.phishing.prompt import SYSTEM_PROMPT
from app.agents.phishing.state import PhishingState
from app.agents.phishing.tools import analyze_url_or_domain
from app.core.logging import get_logger
from app.llm.factory import (
    LlmNotConfiguredError,
    extract_message_text,
    require_configured_chat_model,
)
from app.parsers import ParseError
from app.parsers import email as email_parser

logger = get_logger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "safe": Severity.info,
}


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

async def scan(state: PhishingState) -> dict[str, Any]:
    """Run DNS + HTTP checks against ``asset`` when no email artifact is given."""
    if state.get("raw_input", "").strip():
        return {"scan_info": {"status": "provided", "tool": state.get("source", "")}}

    target = (state.get("asset") or "").strip()
    if not target:
        return {"scan_info": {"status": "no-target", "tool": state.get("source", "")}}

    if is_local_target(target):
        # A loopback/private host can never be a phishing impersonation; running
        # DNS lookalike checks and an LLM verdict against it only yields noise.
        return {
            "scan_info": {"status": "local-skipped", "tool": "url-scan"},
            "local_target": True,
        }

    result = await analyze_url_or_domain(target)
    logger.info(
        "phishing.scan",
        target=target,
        ok=result["ok"],
        tool=result["tool"],
        length=len(result["output"]),
    )
    return {
        "raw_input": result.get("output", ""),
        "source": result.get("tool", "url-scan"),
        "scan_info": result,
    }


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------

async def normalize(state: PhishingState) -> dict[str, Any]:
    """Extract headers, URLs, and domains using the email parser."""
    raw = state["raw_input"]
    source = state["source"].lower()
    logger.info("phishing.normalize", source=source, length=len(raw))

    parsed_email_dict: dict[str, Any] = {}

    if source == "url-scan":
        # Self-launched DNS + HTTP report from the scan node. Its keys mirror
        # the parsed-email schema, so rules and prompts treat it identically.
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                parsed_email_dict = data
                parsed_flag = True
        except json.JSONDecodeError:
            logger.warning("phishing.normalize.url_scan_unparseable")
    else:
        try:
            parsed = email_parser.parse(raw)
            parsed_email_dict = {
                "subject": parsed.subject,
                "sender": parsed.sender,
                "sender_domain": parsed.sender_domain,
                "display_name": parsed.display_name,
                "reply_to": parsed.reply_to,
                "reply_to_domain": parsed.reply_to_domain,
                "spf_result": parsed.spf_result,
                "dkim_result": parsed.dkim_result,
                "dmarc_result": parsed.dmarc_result,
                "links": parsed.links,
                "link_domains": parsed.link_domains,
                "urgency_phrases": parsed.urgency_phrases,
                "brand_keywords": parsed.brand_keywords,
            }
            parsed_flag = True
        except ParseError as exc:
            logger.warning("phishing.normalize.parse_failed", source=source, error=str(exc))
            parsed_flag = False

    return {
        "normalized": {"source": source, "byte_length": len(raw), "parsed": parsed_flag},
        "parsed_email": parsed_email_dict,
    }


# ---------------------------------------------------------------------------
# rule_check
# ---------------------------------------------------------------------------

async def rule_check(state: PhishingState) -> dict[str, Any]:
    """Apply deterministic rules from the PDF."""
    parsed = state.get("parsed_email", {})
    if not parsed:
        return {"rule_hits": []}

    hits: list[str] = []

    # Auth failures
    if parsed.get("spf_result") in ("fail", "softfail"):
        hits.append(f"SPF alignment failed ({parsed['spf_result']})")
    if parsed.get("dkim_result") == "fail":
        hits.append("DKIM signature validation failed")
    if parsed.get("dmarc_result") == "fail":
        hits.append("DMARC policy failed")

    # Domain mismatch
    sender_domain = parsed.get("sender_domain", "")
    reply_to_domain = parsed.get("reply_to_domain", "")
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        hits.append(
            f"Reply-To domain ({reply_to_domain}) differs from sender domain ({sender_domain})"
        )

    # Display name spoofing (heuristic)
    brand_keywords = parsed.get("brand_keywords", [])
    display_name = parsed.get("display_name", "").lower()
    for brand in brand_keywords:
        if brand in display_name and brand not in sender_domain.lower():
            hits.append(
                "Impersonation indicator: Display name claims "
                f"'{brand}' but domain is '{sender_domain}'"
            )

    # Urgency
    urgency = parsed.get("urgency_phrases", [])
    if urgency:
        hits.append(f"Urgency/pressure language detected: {', '.join(urgency)}")

    # Links
    link_domains = parsed.get("link_domains", [])
    if link_domains:
        if len(link_domains) > 5:
            hits.append("High number of distinct external domains in links")
        # Example of a simple lookalike check (could be expanded)
        for domain in link_domains:
            for brand in brand_keywords:
                if brand in domain and brand != domain:
                    hits.append(f"Suspicious link domain contains brand keyword: {domain}")

    logger.info("phishing.rule_check", hit_count=len(hits))
    return {"rule_hits": hits}


# ---------------------------------------------------------------------------
# reason
# ---------------------------------------------------------------------------

async def reason(state: PhishingState) -> dict[str, Any]:
    """Call the LLM with rule hits and parsed email data to get a verdict."""
    fenced = wrap_untrusted("email or URL artifact", state["raw_input"])
    parsed = state.get("parsed_email", {})
    rule_hits = state.get("rule_hits", [])

    context_lines = []
    if parsed:
        context_lines.append(f"Parsed Email Data:\n{json.dumps(parsed, indent=2)}")
    if rule_hits:
        context_lines.append("Deterministic Rule Hits:\n" + "\n".join(f"- {h}" for h in rule_hits))

    context_block = "\n".join(context_lines)
    human_content = f"{context_block}\n\n{fenced}" if context_block else fenced

    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=human_content)]

    verdict = None
    explanation = None
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
        verdict = data.get("verdict", "suspicious")
        explanation = data.get("explanation", "")
        # Store the whole object to pass to emit_findings
        raw_findings = [data]
        logger.info("phishing.reason", verdict=verdict, llm_invoked=True)
    except LlmNotConfiguredError:
        logger.warning("phishing.reason.no_llm", llm_invoked=False)
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.warning("phishing.reason.parse_failed", error=str(exc))
    except Exception as exc:
        logger.warning("phishing.reason.llm_error", error=str(exc), llm_invoked=False)

    return {
        "messages": messages,
        "verdict": verdict,
        "explanation": explanation,
        "raw_findings": raw_findings,
    }


# ---------------------------------------------------------------------------
# emit_findings
# ---------------------------------------------------------------------------

async def emit_findings(state: PhishingState) -> dict[str, Any]:
    """Produce contract-shaped findings based on verdict and rules."""
    source = state["source"]
    asset = state["asset"]

    if state.get("local_target"):
        from datetime import UTC, datetime

        logger.info("phishing.emit_findings", count=0, reason="local_target")
        return {"findings": [FindingCreate(
            agent=AgentKind.phishing,
            finding_type=FindingType.informational,
            title="Phishing analysis skipped: local target",
            description=(
                "The target resolves to a loopback or private network host, which cannot "
                "be a phishing impersonation. DNS lookalike checks and an LLM verdict "
                "were skipped for this target."
            ),
            severity=Severity.info,
            confidence=0.0,
            source=source,
            asset=asset,
            evidence={"reason": "local target"},
            recommendation=None,
            raw_reference=None,
            detected_at=datetime.now(UTC),
        )]}

    raw_findings = state.get("raw_findings", [])
    rule_hits = state.get("rule_hits", [])

    if not raw_findings and not rule_hits:
        finding = placeholder_finding(
            agent=AgentKind.phishing,
            source=source,
            asset=asset,
            raw_input=state["raw_input"],
            summary="No phishing indicators detected by rules, and LLM reasoning is not available.",
        )
        return {"findings": [finding]}

    from datetime import UTC, datetime
    findings: list[FindingCreate] = []

    # If we have an LLM verdict
    if raw_findings:
        raw = raw_findings[0]
        verdict = str(raw.get("verdict", "safe")).lower()

        if verdict in ("phishing", "suspicious"):
            sev_str = str(raw.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.medium)
            confidence = float(raw.get("confidence", 0.8))

            evidence = {
                "verdict": verdict,
                "explanation": raw.get("explanation", ""),
                "key_indicators": raw.get("key_indicators", []) + rule_hits,
            }

            findings.append(FindingCreate(
                agent=AgentKind.phishing,
                finding_type=resolve_finding_type(raw, FindingType.weak_configuration),
                title=f"Phishing analysis: {verdict.capitalize()}",
                description=raw.get("explanation", "Suspicious email detected"),
                severity=severity,
                confidence=confidence,
                source=source,
                asset=asset,
                evidence=evidence,
                recommendation=(
                    "Block sender, delete email, investigate clicked links if applicable"
                ),
                raw_reference=None,
                detected_at=datetime.now(UTC),
            ))
    elif rule_hits:
        # Fallback to pure rule-based finding if LLM is disabled
        findings.append(FindingCreate(
            agent=AgentKind.phishing,
            finding_type=FindingType.weak_configuration,
            title=f"Phishing analysis: {len(rule_hits)} rule indicators triggered",
            description="Deterministic rules identified suspicious indicators.",
            severity=Severity.medium,
            confidence=0.8,
            source=source,
            asset=asset,
            evidence={"rule_hits": rule_hits, "llm_available": False},
            recommendation="Review email manually based on rule hits.",
            raw_reference=None,
            detected_at=datetime.now(UTC),
        ))

    logger.info("phishing.emit_findings", count=len(findings))
    return {"findings": findings}
