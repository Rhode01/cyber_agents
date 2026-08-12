"""Detecting content aimed at the model rather than at the recipient.

Unique among these rules in who it protects. The other five tell an analyst something
about a message; this one notices that the message is trying to talk to the system
analysing it — and it runs *before* any model sees the content, so the finding survives
even if the attempt succeeds.

That ordering is the entire point. The model is also asked to report whether it felt
addressed (``InjectionReport`` in the assessment schema), but a model that has been
successfully steered is exactly the one that will report ``none``. So there are two
independent detectors and **either firing is enough**: this one catches what a
compliant model would rather not mention, and the model catches phrasings no pattern
anticipated.

Patterns, not a model, on purpose. A classifier here would be one more thing that can
be talked out of its answer.
"""

from __future__ import annotations

import re
from typing import Final

from cyber_contracts import NormalizedMessage, Severity

from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)

# Attempts to overwrite the instructions the model was given.
_OVERRIDE_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "instruction-override",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
            r"\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,40}?"
            r"\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions"
            r"|guideline|guidelines|policy|policies|context)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "new-instructions",
        re.compile(
            r"\b(new|updated|revised|following|these)\s+(instruction|instructions|rules|"
            r"directive|directives|task)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict-dictation",
        re.compile(
            r"\b(mark|classify|report|label|treat|consider|rate)\b[^.\n]{0,30}?"
            r"\b(as\s+)?(safe|clean|legitimate|benign|not\s+phishing|harmless|trusted)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "suppression-request",
        re.compile(
            r"\b(do\s+not|don't|never)\b[^.\n]{0,30}?"
            r"\b(report|flag|raise|mention|include|alert|warn)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "configuration-exfiltration",
        re.compile(
            r"\b(reveal|show|print|repeat|output|disclose|list|dump)\b[^.\n]{0,30}?"
            r"\b(system\s+prompt|your\s+prompt|your\s+instructions|your\s+rules|"
            r"api\s+key|credentials|configuration|the\s+rules\s+you)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role-impersonation",
        re.compile(
            r"(^|\n)\s*(system|assistant|developer|tool)\s*[:>\]]",
            re.IGNORECASE,
        ),
    ),
    (
        "mode-switch",
        re.compile(
            r"\b(you\s+are\s+now|enter|switch\s+to|activate|enable)\b[^.\n]{0,30}?"
            r"\b(maintenance|debug|developer|admin|god|unrestricted|jailbreak|dan)\b"
            r"[^.\n]{0,15}?\b(mode)\b",
            re.IGNORECASE,
        ),
    ),
)

# Attempts to close the untrusted fence early and continue as trusted text.
_FENCE_PATTERN: Final = re.compile(
    r"<<<\s*/?\s*untrusted[_a-z0-9]*\s*(begin|end)?\s*>>>", re.IGNORECASE
)

# Chat-template markers. If any of these appear in a phishing email, they are there to
# be interpreted, not read.
_TEMPLATE_PATTERN: Final = re.compile(
    r"(<\|(im_start|im_end|endoftext|system|user|assistant)\|>"
    r"|\[/?INST\]|<</SYS>>|###\s*(Instruction|System|Response)\s*:)",
    re.IGNORECASE,
)

MAX_EXCERPT_CHARS: Final = 240


def _excerpt(text: str, match: re.Match[str]) -> str:
    """A bounded window around a match, so evidence shows context without the payload."""
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)
    window = text[start:end].replace("\n", " ").strip()
    return window[:MAX_EXCERPT_CHARS]


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Every injection indicator this message earns.

    At most one indicator per technique across the whole message: a body repeating
    "ignore previous instructions" nine times is one attempt, and letting it produce
    nine indicators would let an attacker crowd out the real findings from a capped
    prompt.
    """
    # Subject and body are searched together, plus the attachment filenames, because a
    # filename reaches the prompt too.
    haystacks: list[tuple[str, str]] = [
        ("subject", message.subject),
        ("body", message.body_text),
    ]
    haystacks.extend(
        (f"attachment:{attachment.filename}", attachment.filename)
        for attachment in message.attachments
    )
    haystacks.extend(
        (f"link:{position}", link.anchor_text)
        for position, link in enumerate(message.links)
        if link.anchor_text
    )

    found: list[Indicator] = []
    seen_techniques: set[str] = set()

    for locus, text in haystacks:
        if not text.strip():
            continue

        for technique, pattern in _OVERRIDE_PATTERNS:
            if technique in seen_techniques:
                continue
            match = pattern.search(text)
            if match is None:
                continue
            seen_techniques.add(technique)
            found.append(
                make_indicator(
                    rule_id=f"injection-{technique}",
                    category=IndicatorCategory.injection,
                    locus=locus,
                    fact=(
                        f"The {locus} contains text addressed to an automated analyser "
                        f"rather than to a reader ({technique.replace('-', ' ')}): "
                        f"{_excerpt(text, match)!r}"
                    ),
                    weight=0.85,
                    severity_floor=Severity.high,
                    rationale=(
                        "Content trying to instruct the system that analyses it is an "
                        "attack on the analysis, not a property of the mail. It is "
                        "reported as a finding and never followed."
                    ),
                    evidence={"technique": technique, "locus": locus,
                              "excerpt": _excerpt(text, match)},
                    discriminator=technique,
                )
            )

        if "fence-escape" not in seen_techniques:
            fence = _FENCE_PATTERN.search(text)
            if fence is not None:
                seen_techniques.add("fence-escape")
                found.append(
                    make_indicator(
                        rule_id="injection-fence-escape",
                        category=IndicatorCategory.injection,
                        locus=locus,
                        fact=(
                            f"The {locus} contains a copy of this platform's untrusted-"
                            f"content delimiter, an attempt to end the quoted block early "
                            f"and have the rest read as trusted: {_excerpt(text, fence)!r}"
                        ),
                        weight=0.95,
                        severity_floor=Severity.high,
                        rationale=(
                            "Reproducing the internal marker means the sender knows how "
                            "the content is fenced and is targeting this pipeline "
                            "specifically. The fence rewrites nested markers, so the "
                            "attempt fails - but that it was made is the finding."
                        ),
                        evidence={"technique": "fence-escape", "locus": locus,
                                  "excerpt": _excerpt(text, fence)},
                        discriminator="fence-escape",
                    )
                )

        if "chat-template" not in seen_techniques:
            template = _TEMPLATE_PATTERN.search(text)
            if template is not None:
                seen_techniques.add("chat-template")
                found.append(
                    make_indicator(
                        rule_id="injection-chat-template",
                        category=IndicatorCategory.injection,
                        locus=locus,
                        fact=(
                            f"The {locus} contains chat-template control tokens, which "
                            f"exist only to be interpreted by a model: "
                            f"{_excerpt(text, template)!r}"
                        ),
                        weight=0.90,
                        severity_floor=Severity.high,
                        rationale=(
                            "These markers delimit turns in a model's own transcript "
                            "format. Nothing in ordinary correspondence contains them."
                        ),
                        evidence={"technique": "chat-template", "locus": locus,
                                  "excerpt": _excerpt(text, template)},
                        discriminator="chat-template",
                    )
                )

    return found


def fired(indicators: list[Indicator]) -> bool:
    """Did the deterministic detector find anything?

    Used by ``emit_findings`` alongside the model's own report, so either source can
    raise the injection finding.
    """
    return any(
        indicator.category is IndicatorCategory.injection for indicator in indicators
    )
