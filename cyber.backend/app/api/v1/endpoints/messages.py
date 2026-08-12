"""Message intake endpoints.

Two ways in, one pipeline:

* ``POST /messages`` takes an uploaded ``.eml``;
* ``POST /messages/url`` takes a URL or domain an analyst pasted in.

Both are asynchronous for the same reason scan intake is: parsing, optional DNS
and RDAP lookups, and an LLM assessment take tens of seconds, which is far too
long to hold an HTTP request open. Both return **202** with an id, and the client
polls ``GET /messages/{id}`` until the status is ``completed`` or ``failed``.

The format is sniffed at upload rather than in the job, so a file that is not a
message is rejected immediately with a 415 instead of becoming a failed row the
analyst has to go and read.
"""

from __future__ import annotations

import hashlib
from typing import Annotated
from uuid import UUID

from cyber_contracts import MessageFormat, MessageStatus, MessageVerdict
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status

from app import crud
from app.api.deps import SessionDep, SettingsDep
from app.core.logging import get_logger
from app.core.security import CurrentPrincipal
from app.core.urls import InvalidSubmittedUrlError, validate_submitted_url
from app.models.message import MAX_RAW_CONTENT_BYTES, Message
from app.schemas.message import MessageList, MessageRead, UrlSubmit
from app.services.ingestion.errors import ScanParseError
from app.services.ingestion.messages import detect_message_format
from app.tasks.message_tasks import enqueue_message_analysis

logger = get_logger(__name__)

router = APIRouter(prefix="/messages", tags=["messages"])

_READ_CHUNK = 64 * 1024


async def _read_capped(upload: UploadFile) -> bytes:
    """Read an upload, refusing anything over the cap.

    Chunked so an oversized file is rejected without first being held in memory.
    """
    chunks: list[bytes] = []
    total = 0
    while chunk := await upload.read(_READ_CHUNK):
        total += len(chunk)
        if total > MAX_RAW_CONTENT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Messages are limited to {MAX_RAW_CONTENT_BYTES // (1024 * 1024)} MB.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "",
    response_model=MessageRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload an email message and queue it for phishing analysis",
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "The upload was empty."},
        status.HTTP_413_CONTENT_TOO_LARGE: {"description": "Above the size cap."},
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"description": "Not an email message."},
    },
)
async def upload_message(
    session: SessionDep,
    settings: SettingsDep,
    principal: CurrentPrincipal,
    file: Annotated[UploadFile, File(description="An RFC 5322 message, normally a .eml export.")],
    enrich: Annotated[
        bool,
        Form(
            description="Fetch linked pages to follow redirects and look for a "
            "credential form. This contacts the suspect host."
        ),
    ] = False,
) -> MessageRead:
    """Accept a message, persist it, and hand it to the worker."""
    del principal

    raw = await _read_capped(file)
    if not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded file is empty."
        )

    try:
        detected = detect_message_format(raw)
    except ScanParseError as err:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(err)
        ) from err

    message = Message(
        filename=(file.filename or "message.eml")[:255],
        format=detected.value,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        status=MessageStatus.pending.value,
        # latin-1 round-trips every byte, so `raw_content.encode("latin-1")` is
        # byte-identical to the upload. Mail is frequently not valid UTF-8, and a
        # lossy store would change the bytes the parser and the sha256 see.
        raw_content=raw.decode("latin-1"),
    )
    session.add(message)
    await session.commit()
    await session.refresh(message)

    message.job_id = await enqueue_message_analysis(settings.redis_url, message.id, enrich=enrich)
    await session.commit()
    await session.refresh(message)

    logger.info(
        "message.uploaded",
        message_id=str(message.id),
        size_bytes=message.size_bytes,
        enrich=enrich,
        job_id=message.job_id,
    )
    return MessageRead.model_validate(message)


@router.post(
    "/url",
    response_model=MessageRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a URL or domain for phishing analysis",
    responses={
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "Not an http(s) URL, or it names a local or private address."
        }
    },
)
async def submit_url(
    payload: UrlSubmit,
    session: SessionDep,
    settings: SettingsDep,
    principal: CurrentPrincipal,
) -> MessageRead:
    """Accept a URL, persist it, and hand it to the worker.

    Validation here is syntactic and refuses addresses that obviously cannot be a
    phishing host. It is deliberately **not** the SSRF control - that is enforced
    per redirect hop against resolved addresses in the ai.engine.
    """
    del principal

    try:
        url = validate_submitted_url(payload.url)
    except InvalidSubmittedUrlError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(err)
        ) from err

    message = Message(
        filename=url[:255],
        format=MessageFormat.url.value,
        size_bytes=len(url.encode("utf-8")),
        sha256=hashlib.sha256(url.encode("utf-8")).hexdigest(),
        submitted_url=url,
        status=MessageStatus.pending.value,
        raw_content=None,
    )
    session.add(message)
    await session.commit()
    await session.refresh(message)

    message.job_id = await enqueue_message_analysis(
        settings.redis_url, message.id, enrich=payload.enrich
    )
    await session.commit()
    await session.refresh(message)

    logger.info(
        "message.url_submitted",
        message_id=str(message.id),
        enrich=payload.enrich,
        job_id=message.job_id,
    )
    return MessageRead.model_validate(message)


@router.get("", response_model=MessageList, summary="List submitted messages")
async def list_messages(
    session: SessionDep,
    principal: CurrentPrincipal,
    message_status: Annotated[
        MessageStatus | None, Query(alias="status", description="Filter by status.")
    ] = None,
    verdict: Annotated[MessageVerdict | None, Query(description="Filter by verdict.")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> MessageList:
    """Return a page of messages, newest first."""
    del principal

    filters = crud.message.build_filters(status=message_status, verdict=verdict)
    total = await crud.message.count(session, filters=filters)
    rows = await crud.message.get_multi(
        session,
        filters=filters,
        order_by=crud.message.newest_first(),
        limit=limit,
        offset=offset,
    )

    return MessageList(
        items=[MessageRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{message_id}", response_model=MessageRead, summary="Fetch one message")
async def get_message(
    message_id: UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> MessageRead:
    """Return one message. This is the endpoint the frontend polls after submitting."""
    del principal
    row = await crud.message.get(session, message_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
    return MessageRead.model_validate(row)
