"""Live context, gathered through the MCP server.

The ai.engine holds no database, and this module is why it also holds no egress: every
lookup here is an MCP tool call. The MCP server owns the network, the target policy and
the hardened fetch; this file decides what to ask for and how to turn answers into
indicators.

**Invariant: enrichment may only add signal.** It can append indicators and it can
annotate the report. It can never remove an indicator, lower a score, or clear a verdict.
A failed lookup, an unreachable MCP server and a disabled policy all produce the same
outcome - fewer details, identical correctness - because the alternative is a phishing
message that looks clean because a DNS query timed out.

``mcp.client.open_tools`` already yields ``None`` when the server is unreachable, so the
degraded path is one guard rather than a parallel implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from cyber_contracts import EnrichmentPolicy, NormalizedMessage, Severity

from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)
from app.agents.phishing.lookalike import registrable_domain
from app.core.logging import get_logger
from app.mcp.client import open_tools

logger = get_logger(__name__)

DNS_RECORDS_TOOL: Final = "dns_records"
DOMAIN_AGE_TOOL: Final = "lookup_domain_age"
FETCH_URL_TOOL: Final = "fetch_url"

YOUNG_DOMAIN_DAYS: Final = 45
"""Below this, a domain is young enough to be worth reporting on its own.

Phishing infrastructure is typically days old. Legitimate organisations occasionally do
send from a new domain - a rebrand, a campaign microsite - so this is an indicator rather
than a verdict."""


@dataclass(slots=True)
class EnrichmentResult:
    """What enrichment produced: extra indicators, plus a report for the evidence."""

    report: dict[str, Any] = field(default_factory=dict)
    indicators: list[Indicator] = field(default_factory=list)


async def gather(
    *,
    message: NormalizedMessage,
    policy: EnrichmentPolicy,
    existing: list[Indicator],
) -> EnrichmentResult:
    """Run whatever lookups the policy permits and the server offers."""
    del existing  # Reserved for skipping lookups already answered by a rule; not used yet.

    result = EnrichmentResult(report={"available": False, "lookups": {}})
    sender_domain = registrable_domain(message.sender.domain)
    targets = _fetch_targets(message, policy)

    if not sender_domain and not targets:
        result.report["reason"] = "nothing to look up"
        return result

    async with open_tools() as tools:
        if tools is None:
            # Not an error. The rule engine has already produced its findings and the
            # assessment proceeds; only the extra detail is missing.
            logger.info("phishing.enrich.unavailable")
            result.report["reason"] = (
                "the MCP server was unreachable, so no live lookups were performed"
            )
            return result

        result.report["available"] = True
        result.report["tools_offered"] = sorted(tools.available)

        if policy.resolve_dns and sender_domain and tools.has(DNS_RECORDS_TOOL):
            await _dns(tools, sender_domain, message, result)

        if policy.domain_age and sender_domain and tools.has(DOMAIN_AGE_TOOL):
            await _domain_age(tools, sender_domain, result)

        if policy.fetch_urls and targets and tools.has(FETCH_URL_TOOL):
            await _fetch(tools, targets, result)
        elif targets and not policy.fetch_urls:
            result.report["lookups"]["fetch_url"] = {
                "skipped": "not requested - fetching contacts the suspect host"
            }

    return result


def _fetch_targets(message: NormalizedMessage, policy: EnrichmentPolicy) -> list[str]:
    """Which links are worth resolving, most interesting first.

    Bounded by ``policy.max_urls``. Shorteners come first because resolving one is the
    only way to learn anything about it at all.
    """
    ordered = sorted(
        (link for link in message.links if link.scheme in {"http", "https"} and link.host),
        key=lambda link: (0 if len(link.host) <= 12 else 1, link.host),
    )
    seen: set[str] = set()
    targets: list[str] = []
    for link in ordered:
        if link.url in seen:
            continue
        seen.add(link.url)
        targets.append(link.url)
        if len(targets) >= policy.max_urls:
            break
    return targets


async def _dns(
    tools: Any, domain: str, message: NormalizedMessage, result: EnrichmentResult
) -> None:
    """Compare the domain's published policy against what the headers claimed."""
    answer = await tools.call(DNS_RECORDS_TOOL, {"domain": domain})
    result.report["lookups"]["dns_records"] = answer
    if not answer.get("ok"):
        return

    has_spf = bool(answer.get("spf"))
    has_dmarc = bool(answer.get("dmarc"))

    # The interesting case: the message *claimed* a pass, and the domain publishes no
    # policy that could have produced one. That claim was decorative.
    if message.auth.spf == "pass" and not has_spf:
        result.indicators.append(
            make_indicator(
                rule_id="enrich-spf-claim-unsupported",
                category=IndicatorCategory.authentication,
                locus="header:Authentication-Results",
                fact=(
                    f"The message reports 'spf=pass', but {domain!r} publishes no SPF "
                    f"record, so no verifier could have produced that result."
                ),
                weight=0.85,
                severity_floor=Severity.high,
                rationale=(
                    "An Authentication-Results header is just text the delivery path "
                    "wrote. Checking it against the domain's real DNS is the only way to "
                    "tell a genuine pass from a fabricated one."
                ),
                evidence={"domain": domain, "claimed": "pass", "published_spf": False},
            )
        )

    if not has_dmarc and message.auth.dmarc != "fail":
        result.indicators.append(
            make_indicator(
                rule_id="enrich-no-dmarc-policy",
                category=IndicatorCategory.authentication,
                locus="dns:_dmarc",
                fact=f"{domain!r} publishes no DMARC policy, so its mail cannot be aligned.",
                weight=0.40,
                severity_floor=Severity.low,
                rationale=(
                    "Without a DMARC record the domain has no protection against being "
                    "spoofed, and a receiver has nothing to enforce. Common among smaller "
                    "senders, so weak on its own."
                ),
                evidence={"domain": domain, "published_dmarc": False},
            )
        )


async def _domain_age(tools: Any, domain: str, result: EnrichmentResult) -> None:
    """A newly registered sending domain is strong signal."""
    answer = await tools.call(DOMAIN_AGE_TOOL, {"domain": domain})
    result.report["lookups"]["lookup_domain_age"] = answer
    if not answer.get("ok"):
        return

    age = answer.get("age_days")
    if not isinstance(age, int | float) or age < 0 or age >= YOUNG_DOMAIN_DAYS:
        return

    result.indicators.append(
        make_indicator(
            rule_id="enrich-young-sender-domain",
            category=IndicatorCategory.identity,
            locus="header:From",
            fact=(
                f"The sending domain {domain!r} was registered {int(age)} day(s) ago, "
                f"which is recent enough to have been set up for this campaign."
            ),
            weight=0.75,
            severity_floor=Severity.high,
            rationale=(
                "Phishing infrastructure is usually days old, because domains get "
                "reported and burned. Legitimate senders occasionally use a new domain, "
                "so this is an indicator rather than a verdict."
            ),
            evidence={
                "domain": domain,
                "age_days": age,
                "registered": answer.get("registered"),
            },
        )
    )


async def _fetch(tools: Any, targets: list[str], result: EnrichmentResult) -> None:
    """Follow the links, and report what the destination page actually is.

    The MCP server does the hardening - per-hop address checks, hop and body caps - and
    never renders or executes anything. What comes back is structure: the final host, the
    redirect chain, whether there is a password field, and where any form submits.
    """
    fetched: list[dict[str, Any]] = []
    for url in targets:
        answer = await tools.call(FETCH_URL_TOOL, {"url": url})
        fetched.append({"url": url, "result": answer})
        if not answer.get("ok"):
            continue

        final_host = str(answer.get("final_host") or "")
        chain = answer.get("redirect_chain") or []
        crossed = [host for host in chain if host and host != final_host]

        if answer.get("password_field") and final_host:
            result.indicators.append(
                make_indicator(
                    rule_id="enrich-credential-form",
                    category=IndicatorCategory.url,
                    locus=f"fetched:{final_host}",
                    fact=(
                        f"A linked page at {final_host!r} presents a password field, so it "
                        f"is asking the recipient for credentials."
                    ),
                    weight=0.90,
                    severity_floor=Severity.high,
                    rationale=(
                        "A link from an unauthenticated message leading to a credential "
                        "prompt is the mechanism of the attack, not a circumstance around "
                        "it."
                    ),
                    evidence={
                        "url": url,
                        "final_host": final_host,
                        "title": answer.get("title", ""),
                        "form_hosts": answer.get("form_hosts", []),
                    },
                    discriminator=final_host,
                )
            )

        if len(crossed) >= 2:
            result.indicators.append(
                make_indicator(
                    rule_id="enrich-redirect-chain",
                    category=IndicatorCategory.url,
                    locus=f"fetched:{final_host or url}",
                    fact=(
                        f"A link redirected across {len(crossed)} different hosts before "
                        f"arriving at {final_host!r}."
                    ),
                    weight=0.65,
                    severity_floor=Severity.medium,
                    rationale=(
                        "Chained redirects across unrelated domains are used to break the "
                        "link between what a scanner sees and where a person lands."
                    ),
                    evidence={"url": url, "redirect_chain": chain, "final_host": final_host},
                    discriminator=final_host or url,
                )
            )

    result.report["lookups"]["fetch_url"] = {"count": len(fetched), "results": fetched}
