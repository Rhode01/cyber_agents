"""arq tasks for phishing message intake.

``analyze_message``  a submitted email or URL -> parse -> ai.engine -> findings

Separate from ``scan_tasks`` because the two intakes fail for different reasons
and write to different tables, and because a scan job and a message job sharing a
module would mean every change to one risks the other.

The job owns a session for its whole lifetime and commits as it goes, so a polling
client sees real progress rather than a jump from queued to done. It contains no
detection logic - that lives in the ai.engine.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from cyber_contracts import (
    SEVERITY_ORDER,
    AuthResults,
    EmailAddress,
    EmailLink,
    EnrichmentPolicy,
    FindingCreate,
    MessageFormat,
    MessageStatus,
    MessageVerdict,
    NormalizedMessage,
    PhishingAnalyzeRequest,
    Severity,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.session import get_sessionmaker
from app.models.message import Message
from app.services.ai_engine.client import AiEngineClient, AiEngineError
from app.services.ingestion.email import parse_email_mime
from app.services.ingestion.errors import ScanParseError
from app.services.orchestration import persist_findings

logger = get_logger(__name__)

# Which verdict a set of findings adds up to. Read off the most severe finding
# rather than an average: one critical indicator among nine harmless ones is a
# phishing message, and averaging would bury it.
_VERDICT_BY_SEVERITY: dict[Severity, MessageVerdict] = {
    Severity.critical: MessageVerdict.phishing,
    Severity.high: MessageVerdict.phishing,
    Severity.medium: MessageVerdict.suspicious,
    Severity.low: MessageVerdict.suspicious,
    Severity.info: MessageVerdict.clean,
}


def verdict_for(findings: list[FindingCreate]) -> MessageVerdict:
    """Reduce a batch of findings to one headline verdict.

    An empty batch is ``clean`` rather than null: reaching this function at all
    means the message was successfully analysed, and "analysed, nothing found" has
    to stay distinguishable from "never analysed", which is what a null verdict
    means on the row.
    """
    if not findings:
        return MessageVerdict.clean
    worst = max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
    return _VERDICT_BY_SEVERITY[worst.severity]


def url_as_message(url: str) -> NormalizedMessage:
    """Wrap a bare URL in the shape the phishing rule engine consumes.

    A URL submission has no headers, so the authentication and identity rule
    families simply find nothing - which is correct, not a gap. Presenting it as a
    ``NormalizedMessage`` means the URL rules are the same code in both paths
    rather than a second implementation that drifts.
    """
    host = url.split("://", 1)[-1].split("/")[0].split("@")[-1]
    return NormalizedMessage(
        format=MessageFormat.url,
        sender=EmailAddress(display_name="", address="", domain=""),
        auth=AuthResults(spf="none", dkim="none", dmarc="none", present=False),
        links=[
            EmailLink(
                url=url,
                scheme=url.split("://", 1)[0].lower(),
                host=host.rsplit(":", 1)[0] if host.count(":") == 1 else host,
                anchor_text="",
            )
        ],
    )


async def _fail(session: AsyncSession, message: Message, reason: str) -> dict[str, Any]:
    """Mark a message failed with a reason an operator can act on.

    This is the "fail loudly" path. Nothing partial is persisted, the row is
    retryable, and the frontend renders ``error`` verbatim rather than showing a
    verdict that was never actually reached. ``verdict`` stays null, which is
    deliberately different from ``clean``.
    """
    message.status = MessageStatus.failed.value
    message.error = reason[:4000]
    message.verdict = None
    await session.commit()
    logger.warning("message.failed", message_id=str(message.id), reason=reason)
    return {"message_id": str(message.id), "status": MessageStatus.failed.value, "error": reason}


async def analyze_message(
    ctx: dict[str, Any], message_id: str, *, enrich: bool = False
) -> dict[str, Any]:
    """Parse a submitted message, have the ai.engine assess it, and persist findings.

    Status advances pending -> parsing -> analyzing -> completed, committing at
    each step so the frontend's poll shows real progress.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        message = await session.get(Message, UUID(message_id))
        if message is None:
            logger.warning("message.missing", message_id=message_id, job_id=ctx.get("job_id"))
            return {"message_id": message_id, "status": "missing"}

        logger.info("message.analyze.start", message_id=message_id, job_id=ctx.get("job_id"))

        # ---- parse ---------------------------------------------------------
        message.status = MessageStatus.parsing.value
        await session.commit()

        message_format = MessageFormat(message.format)
        if message_format is MessageFormat.url:
            if not message.submitted_url:
                return await _fail(session, message, "The stored submission has no URL.")
            normalized = url_as_message(message.submitted_url)
            asset: str | None = message.submitted_url
            source = "url-submission"
        else:
            if not message.raw_content:
                return await _fail(session, message, "The stored message has no content to parse.")
            try:
                # latin-1 recovers the exact submitted bytes - see the note on
                # Message.raw_content for why it is stored that way.
                normalized = parse_email_mime(message.raw_content.encode("latin-1"))
            except ScanParseError as err:
                return await _fail(session, message, f"Could not parse the message: {err}")
            asset = normalized.sender.address or None
            source = "eml-upload"

        message.link_count = normalized.link_count
        message.attachment_count = normalized.attachment_count
        message.sender = normalized.sender.address or None
        message.subject = normalized.subject or None
        message.status = MessageStatus.analyzing.value
        await session.commit()

        logger.info(
            "message.parsed",
            message_id=message_id,
            links=normalized.link_count,
            attachments=normalized.attachment_count,
            html=normalized.body_html_present,
        )

        # ---- assess --------------------------------------------------------
        request = PhishingAnalyzeRequest(
            intake_id=message.id,
            source=source,
            asset=asset,
            message=normalized,
            enrichment=EnrichmentPolicy(fetch_urls=enrich),
            context={"filename": message.filename, "sha256": message.sha256},
        )

        client = AiEngineClient()
        try:
            batch = await client.assess_phishing(request)
        except AiEngineError as err:
            detail = f"The ai.engine could not assess this message: {err}"
            if err.status_code is not None:
                detail = f"{detail} (upstream status {err.status_code})"
            return await _fail(session, message, detail)
        finally:
            await client.aclose()

        # ---- persist -------------------------------------------------------
        stamped = [
            finding.model_copy(
                update={"message_id": message.id, "raw_reference": f"message://{message.id}"}
            )
            for finding in batch.findings
        ]
        rows = await persist_findings(session, stamped)

        message.finding_count = len(rows)
        message.verdict = verdict_for(list(batch.findings)).value
        message.status = MessageStatus.completed.value
        message.completed_at = datetime.now(UTC)
        message.error = None
        await session.commit()

        logger.info(
            "message.analyze.done",
            message_id=message_id,
            findings=len(rows),
            verdict=message.verdict,
        )
        return {
            "message_id": message_id,
            "status": MessageStatus.completed.value,
            "verdict": message.verdict,
            "findings": len(rows),
        }


async def enqueue_message_analysis(
    redis_url: str, message_id: UUID, *, enrich: bool = False
) -> str | None:
    """Queue a message for analysis and return its job id."""
    redis = await create_pool(RedisSettings.from_dsn(redis_url))
    try:
        job = await redis.enqueue_job("analyze_message", str(message_id), enrich=enrich)
    finally:
        await redis.aclose()

    if job is None:
        logger.warning("worker.enqueue.deduplicated", message_id=str(message_id))
        return None

    logger.info(
        "worker.enqueue.ok",
        task="analyze_message",
        message_id=str(message_id),
        job_id=job.job_id,
    )
    return job.job_id
