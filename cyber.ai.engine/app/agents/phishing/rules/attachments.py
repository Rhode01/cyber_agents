"""Rules about what is attached, judged from metadata alone.

The parser hashes attachment bytes and discards them, so this module *cannot* inspect
content even if someone later wanted it to. No archive is opened, no macro is
extracted, nothing is executed. That is a deliberate boundary: the platform never
needs to hold a malware sample to report that an ``.exe`` arrived, and holding one
would make this service a place where samples accumulate.

What metadata still tells you is a great deal. A filename with two extensions, a
right-to-left override, or a declared MIME type that disagrees with its own extension
are all disguises, and a disguise is evidence of intent in a way that a file's
contents are not.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from cyber_contracts import EmailAttachment, NormalizedMessage, Severity

from app.agents.phishing import knowledge
from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)

# Characters that reverse or reorder how the rest of a filename renders. U+202E is the
# classic: "invoice‮fdp.exe" displays as "invoiceexe.pdf".
_BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‏‎")


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Every attachment indicator this message earns."""
    found: list[Indicator] = []
    for attachment in message.attachments:
        locus = f"attachment:{attachment.filename or '(unnamed)'}"
        found.extend(_bidi_override(attachment, locus))
        found.extend(_double_extension(attachment, locus))
        found.extend(_risky_extension(attachment, locus))
        found.extend(_declared_type_mismatch(attachment, locus))
    return found


def _suffixes(filename: str) -> list[str]:
    """Lower-cased suffixes of a filename, ignoring path separators a sender chose."""
    name = PurePosixPath(filename.replace("\\", "/")).name
    return [suffix.lower() for suffix in PurePosixPath(name).suffixes]


def _bidi_override(attachment: EmailAttachment, locus: str) -> list[Indicator]:
    """A filename containing bidirectional control characters."""
    present = sorted(_BIDI_CONTROLS & set(attachment.filename))
    if not present:
        return []

    codepoints = ", ".join(f"U+{ord(char):04X}" for char in present)
    # Show what it renders as with the controls removed, since the raw string is
    # exactly what makes this hard to read in the first place.
    stripped = "".join(char for char in attachment.filename if char not in _BIDI_CONTROLS)
    return [
        make_indicator(
            rule_id="attachment-bidi-override",
            category=IndicatorCategory.attachment,
            locus=locus,
            fact=(
                f"An attachment filename contains bidirectional control characters "
                f"({codepoints}), which make it display differently from what it is. "
                f"With them removed the name is {stripped!r}."
            ),
            weight=0.90,
            severity_floor=Severity.high,
            rationale=(
                "There is no legitimate reason to put a direction override in a "
                "filename. It exists to make an executable extension render as a "
                "document one."
            ),
            evidence={
                "filename": attachment.filename,
                "without_controls": stripped,
                "controls": codepoints,
                "sha256": attachment.sha256,
            },
        )
    ]


def _double_extension(attachment: EmailAttachment, locus: str) -> list[Indicator]:
    """``invoice.pdf.exe`` - a document extension followed by an executable one."""
    suffixes = _suffixes(attachment.filename)
    if len(suffixes) < 2:
        return []

    risk = knowledge.attachment_risk()
    first, last = suffixes[-2], suffixes[-1]
    if first not in risk.double_extension_first:
        return []
    if last not in risk.executable and last not in risk.macro:
        return []

    return [
        make_indicator(
            rule_id="attachment-double-extension",
            category=IndicatorCategory.attachment,
            locus=locus,
            fact=(
                f"An attachment is named {attachment.filename!r}: it presents as {first} "
                f"but the operating system will treat it as {last}."
            ),
            weight=0.90,
            severity_floor=Severity.critical,
            rationale=(
                "Only the final extension decides what happens on a double-click. A "
                "document extension in front of an executable one is there purely to "
                "make the reader expect a document."
            ),
            evidence={
                "filename": attachment.filename,
                "apparent_type": first,
                "actual_type": last,
                "sha256": attachment.sha256,
            },
            discriminator=f"{first}{last}",
        )
    ]


def _risky_extension(attachment: EmailAttachment, locus: str) -> list[Indicator]:
    """An extension that runs code, carries macros, or hides other files."""
    suffixes = _suffixes(attachment.filename)
    if not suffixes:
        return []
    risk = knowledge.attachment_risk()
    final = suffixes[-1]

    if final in risk.executable:
        return [
            make_indicator(
                rule_id="attachment-executable",
                category=IndicatorCategory.attachment,
                locus=locus,
                fact=f"An attachment {attachment.filename!r} is an executable file type ({final}).",
                weight=0.90,
                severity_floor=Severity.critical,
                rationale=(
                    "Executable attachments run code on the recipient's machine. Almost "
                    "no legitimate business process sends one by mail, and most gateways "
                    "strip them - so one arriving is worth an analyst's attention on its "
                    "own."
                ),
                evidence={"filename": attachment.filename, "extension": final,
                          "size_bytes": attachment.size_bytes, "sha256": attachment.sha256},
                discriminator=final,
            )
        ]

    if final in risk.macro:
        return [
            make_indicator(
                rule_id="attachment-macro-capable",
                category=IndicatorCategory.attachment,
                locus=locus,
                fact=(
                    f"An attachment {attachment.filename!r} is a macro-capable Office "
                    f"format ({final})."
                ),
                weight=0.70,
                severity_floor=Severity.high,
                rationale=(
                    "These formats can carry code that runs once the recipient is talked "
                    "into enabling it, which is what the accompanying message is usually "
                    "for. Legitimate senders normally use the macro-free equivalents."
                ),
                evidence={"filename": attachment.filename, "extension": final,
                          "sha256": attachment.sha256},
                discriminator=final,
            )
        ]

    if final in risk.container:
        return [
            make_indicator(
                rule_id="attachment-container",
                category=IndicatorCategory.attachment,
                locus=locus,
                fact=(
                    f"An attachment {attachment.filename!r} is an archive or disk image "
                    f"({final}), so what it contains is not visible from the message."
                ),
                weight=0.50,
                severity_floor=Severity.medium,
                rationale=(
                    "Containers are how executables get past gateways that would "
                    "otherwise strip them, and disk images additionally strip the "
                    "mark-of-the-web so the file inside opens without a warning. This "
                    "engine reports the container and never opens it."
                ),
                evidence={"filename": attachment.filename, "extension": final,
                          "size_bytes": attachment.size_bytes, "sha256": attachment.sha256},
                discriminator=final,
            )
        ]

    return []


def _declared_type_mismatch(attachment: EmailAttachment, locus: str) -> list[Indicator]:
    """The sender's own client disagreeing with the filename."""
    suffixes = _suffixes(attachment.filename)
    if not suffixes:
        return []
    expected = knowledge.attachment_risk().expected_types.get(suffixes[-1])
    if not expected:
        return []

    declared = attachment.content_type.split(";")[0].strip().lower()
    if not declared or declared in expected:
        return []
    # Generic types are what a client sends when it does not recognise the file, which
    # is ordinary rather than deceptive.
    if declared in {"application/octet-stream", "application/x-download", "binary/octet-stream"}:
        return []

    return [
        make_indicator(
            rule_id="attachment-type-mismatch",
            category=IndicatorCategory.attachment,
            locus=locus,
            fact=(
                f"An attachment named {attachment.filename!r} is declared as {declared!r}, "
                f"but that extension is normally {expected[0]!r}."
            ),
            weight=0.45,
            severity_floor=Severity.low,
            rationale=(
                "The declared type comes from the sending client, so a disagreement with "
                "the filename means either a misconfigured sender or a file renamed to "
                "look like something else. Weak alone, informative alongside anything "
                "else."
            ),
            evidence={
                "filename": attachment.filename,
                "declared_type": declared,
                "expected_types": list(expected),
                "sha256": attachment.sha256,
            },
            discriminator=declared,
        )
    ]
