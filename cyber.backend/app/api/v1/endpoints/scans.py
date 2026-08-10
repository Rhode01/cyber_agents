"""Scan intake endpoints.

Upload is deliberately asynchronous: parsing plus an LLM assessment can take
tens of seconds, which is far too long to hold an HTTP request open. ``POST``
returns **202** with a scan id, and the client polls ``GET /scans/{id}`` until
the status is ``completed`` or ``failed``.

The format is sniffed at upload rather than in the job so an unsupported file is
rejected immediately with a 415, instead of becoming a failed scan the operator
has to go and read.
"""

from __future__ import annotations

import hashlib
from typing import Annotated
from uuid import UUID

from cyber_contracts import ScanFormat, ScanStatus
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select

from app.api.deps import SessionDep, SettingsDep
from app.core.logging import get_logger
from app.core.security import CurrentPrincipal
from app.services.ingestion import ScanParseError, detect_format
from app.services.ingestion.registry import PARSERS
from app.models.scan import MAX_RAW_CONTENT_BYTES, Scan
from app.schemas.scan import ScanList, ScanRead
from app.tasks.scan_tasks import enqueue_scan_analysis

logger = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

_READ_CHUNK = 64 * 1024


async def _read_capped(file: UploadFile) -> bytes:
    """Read an upload, refusing anything over the cap.

    Chunked so an oversized file is rejected without first being held in memory.
    """
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_READ_CHUNK):
        total += len(chunk)
        if total > MAX_RAW_CONTENT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Scan files are limited to {MAX_RAW_CONTENT_BYTES // (1024 * 1024)} MB.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a scanner report and queue it for analysis",
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Not decodable as UTF-8 text."},
        status.HTTP_413_CONTENT_TOO_LARGE: {"description": "Above the size cap."},
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"description": "Unrecognised scanner format."},
    },
)
async def upload_scan(
    session: SessionDep,
    settings: SettingsDep,
    principal: CurrentPrincipal,
    file: Annotated[UploadFile, File(description="Scanner output, e.g. nmap -oX.")],
    asset: Annotated[str | None, Form(max_length=512)] = None,
    scan_format: Annotated[ScanFormat | None, Form()] = None,
) -> ScanRead:
    """Accept a scan, persist it, and hand it to the worker."""
    del principal

    raw = await _read_capped(file)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded file is empty."
        )

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan files must be UTF-8 text.",
        ) from err

    resolved_format = scan_format
    if resolved_format is None:
        try:
            resolved_format = detect_format(content)
        except ScanParseError as err:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(err)
            ) from err

    if resolved_format not in PARSERS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"{resolved_format.value} is recognised but not supported yet.",
        )

    scan = Scan(
        filename=(file.filename or "upload.xml")[:255],
        format=resolved_format.value,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        asset=asset,
        status=ScanStatus.pending.value,
        raw_content=content,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    scan.job_id = await enqueue_scan_analysis(settings.redis_url, scan.id)
    await session.commit()
    await session.refresh(scan)

    logger.info(
        "scan.uploaded",
        scan_id=str(scan.id),
        format=scan.format,
        size_bytes=scan.size_bytes,
        job_id=scan.job_id,
    )
    return ScanRead.model_validate(scan)


@router.get("", response_model=ScanList, summary="List scans")
async def list_scans(
    session: SessionDep,
    principal: CurrentPrincipal,
    scan_status: Annotated[ScanStatus | None, Query(description="Filter by status.")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanList:
    """Return a page of scans, newest first."""
    del principal

    filters = [Scan.status == scan_status.value] if scan_status is not None else []

    total = int(
        (await session.execute(select(func.count()).select_from(Scan).where(*filters))).scalar_one()
    )
    rows = (
        (
            await session.execute(
                select(Scan)
                .where(*filters)
                .order_by(Scan.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )

    return ScanList(
        items=[ScanRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanRead, summary="Fetch one scan")
async def get_scan(
    scan_id: UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> ScanRead:
    """Return one scan. This is the endpoint the frontend polls after upload."""
    del principal
    row = await session.get(Scan, scan_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanRead.model_validate(row)
