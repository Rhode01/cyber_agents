"""Email connect endpoints.

Provides OAuth 2.0 flows for Gmail and Microsoft 365, an IMAP connector
that works with any mail server/domain, plus a unified POST /email/scan
endpoint that pulls emails and runs the phishing agent.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Annotated, Any

from cyberagents_contracts import AgentKind
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.dialects.postgresql import insert

from app.api.deps import AiEngineDep, SessionDep
from app.core.logging import get_logger
from app.core.security import CurrentPrincipal
from app.models.run import Run as RunModel
from app.models.setting import Setting as SettingModel
from app.schemas.agents import AgentRunRequest
from app.schemas.finding import FindingRead
from app.services.ai_engine_client import AiEngineError
from app.services.email_client import (
    GOOGLE_CLIENT_ID_KEY,
    GOOGLE_CLIENT_SECRET_KEY,
    GOOGLE_TOKEN_KEY,
    IMAP_FOLDER_KEY,
    IMAP_HOST_KEY,
    IMAP_PASSWORD_KEY,
    IMAP_PORT_KEY,
    IMAP_USERNAME_KEY,
    MICROSOFT_CLIENT_ID_KEY,
    MICROSOFT_CLIENT_SECRET_KEY,
    MICROSOFT_TENANT_ID_KEY,
    MICROSOFT_TOKEN_KEY,
    format_token,
    gmail_fetch_emails,
    google_auth_url,
    google_exchange_code,
    google_refresh_token,
    imap_fetch_emails,
    imap_verify_connection,
    microsoft_auth_url,
    microsoft_exchange_code,
    microsoft_refresh_token,
    outlook_fetch_emails,
    parse_token,
)
from app.services.orchestration import run_agent

logger = get_logger(__name__)

router = APIRouter(prefix="/email", tags=["email"])

# The redirect URIs the OAuth providers will call back to.
# These go through the frontend (:3000), which forwards the auth code to the
# backend callback so Google/Microsoft only need the site origin registered.
_GOOGLE_REDIRECT = "http://localhost:3000/email/connect/google/callback"
_MICROSOFT_REDIRECT = "http://localhost:3000/email/connect/microsoft/callback"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

async def _get_setting(session: Any, key: str) -> str | None:
    row = await session.get(SettingModel, key)
    return row.value if row else None


async def _upsert_setting(session: Any, key: str, value: str) -> None:
    stmt = insert(SettingModel).values(key=key, value=value)
    stmt = stmt.on_conflict_do_update(
        index_elements=["key"], set_={"value": stmt.excluded.value}
    )
    await session.execute(stmt)
    await session.commit()


# --------------------------------------------------------------------------- #
# Status endpoint
# --------------------------------------------------------------------------- #

class EmailConnectionStatus(BaseModel):
    google_connected: bool
    microsoft_connected: bool
    imap_connected: bool = False
    imap_account: str | None = None


@router.get("/status", response_model=EmailConnectionStatus, summary="Check connected email accounts")
async def email_status(session: SessionDep, principal: CurrentPrincipal) -> EmailConnectionStatus:
    """Return which email providers currently have stored credentials."""
    del principal
    google_token = await _get_setting(session, GOOGLE_TOKEN_KEY)
    microsoft_token = await _get_setting(session, MICROSOFT_TOKEN_KEY)
    imap_host = await _get_setting(session, IMAP_HOST_KEY)
    imap_user = await _get_setting(session, IMAP_USERNAME_KEY)
    return EmailConnectionStatus(
        google_connected=bool(google_token),
        microsoft_connected=bool(microsoft_token),
        imap_connected=bool(imap_host and imap_user),
        imap_account=imap_user,
    )


@router.delete("/disconnect/{provider}", summary="Revoke a connected email account")
async def email_disconnect(
    provider: str,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> dict[str, str]:
    """Remove stored credentials for the given provider (google | microsoft | imap)."""
    del principal
    if provider == "google":
        keys = [GOOGLE_TOKEN_KEY]
    elif provider == "microsoft":
        keys = [MICROSOFT_TOKEN_KEY]
    elif provider == "imap":
        keys = [IMAP_HOST_KEY, IMAP_PORT_KEY, IMAP_USERNAME_KEY, IMAP_PASSWORD_KEY, IMAP_FOLDER_KEY]
    else:
        raise HTTPException(status_code=400, detail="Unknown provider. Use 'google', 'microsoft' or 'imap'.")

    for key in keys:
        row = await session.get(SettingModel, key)
        if row:
            await session.delete(row)
    await session.commit()
    return {"status": "disconnected", "provider": provider}


# --------------------------------------------------------------------------- #
# Google / Gmail OAuth
# --------------------------------------------------------------------------- #

@router.get("/connect/google", summary="Begin Google OAuth flow")
async def connect_google(session: SessionDep, principal: CurrentPrincipal) -> RedirectResponse:
    """Redirect the user to Google's OAuth consent screen."""
    del principal
    client_id = await _get_setting(session, GOOGLE_CLIENT_ID_KEY)
    if not client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Set email_google_client_id in Settings before connecting Google.",
        )
    url = google_auth_url(client_id, _GOOGLE_REDIRECT)
    return RedirectResponse(url)


@router.get("/connect/google/callback", summary="Google OAuth callback")
async def connect_google_callback(
    session: SessionDep,
    principal: CurrentPrincipal,
    code: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """Exchange Google auth code for tokens and store them."""
    del principal
    if error or not code:
        return RedirectResponse(f"http://localhost:3000/settings?email_error={error or 'cancelled'}")

    client_id = await _get_setting(session, GOOGLE_CLIENT_ID_KEY)
    client_secret = await _get_setting(session, GOOGLE_CLIENT_SECRET_KEY)
    if not client_id or not client_secret:
        return RedirectResponse("http://localhost:3000/settings?email_error=missing_credentials")

    try:
        token_data = await google_exchange_code(code, client_id, client_secret, _GOOGLE_REDIRECT)
        await _upsert_setting(session, GOOGLE_TOKEN_KEY, format_token(token_data))
        logger.info("email.google.connected")
        return RedirectResponse("http://localhost:3000/settings?email_connected=google")
    except Exception as exc:
        logger.error("email.google.exchange_failed", error=str(exc))
        return RedirectResponse(f"http://localhost:3000/settings?email_error=exchange_failed")


# --------------------------------------------------------------------------- #
# Microsoft / Outlook OAuth
# --------------------------------------------------------------------------- #

@router.get("/connect/microsoft", summary="Begin Microsoft OAuth flow")
async def connect_microsoft(session: SessionDep, principal: CurrentPrincipal) -> RedirectResponse:
    """Redirect the user to Microsoft's OAuth consent screen."""
    del principal
    client_id = await _get_setting(session, MICROSOFT_CLIENT_ID_KEY)
    tenant_id = await _get_setting(session, MICROSOFT_TENANT_ID_KEY)
    if not client_id or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Set email_microsoft_client_id and email_microsoft_tenant_id in Settings before connecting Microsoft.",
        )
    url = microsoft_auth_url(client_id, tenant_id, _MICROSOFT_REDIRECT)
    return RedirectResponse(url)


@router.get("/connect/microsoft/callback", summary="Microsoft OAuth callback")
async def connect_microsoft_callback(
    session: SessionDep,
    principal: CurrentPrincipal,
    code: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """Exchange Microsoft auth code for tokens and store them."""
    del principal
    if error or not code:
        return RedirectResponse(f"http://localhost:3000/settings?email_error={error or 'cancelled'}")

    client_id = await _get_setting(session, MICROSOFT_CLIENT_ID_KEY)
    client_secret = await _get_setting(session, MICROSOFT_CLIENT_SECRET_KEY)
    tenant_id = await _get_setting(session, MICROSOFT_TENANT_ID_KEY)
    if not client_id or not client_secret or not tenant_id:
        return RedirectResponse("http://localhost:3000/settings?email_error=missing_credentials")

    try:
        token_data = await microsoft_exchange_code(
            code, client_id, client_secret, tenant_id, _MICROSOFT_REDIRECT
        )
        await _upsert_setting(session, MICROSOFT_TOKEN_KEY, format_token(token_data))
        logger.info("email.microsoft.connected")
        return RedirectResponse("http://localhost:3000/settings?email_connected=microsoft")
    except Exception as exc:
        logger.error("email.microsoft.exchange_failed", error=str(exc))
        return RedirectResponse("http://localhost:3000/settings?email_error=exchange_failed")


# --------------------------------------------------------------------------- #
# IMAP / generic mail server (any email domain)
# --------------------------------------------------------------------------- #

class ImapConnectRequest(BaseModel):
    email: str
    host: str
    port: int = 993
    password: str
    folder: str = "INBOX"


@router.post("/connect/imap", summary="Connect any mail server via IMAP")
async def connect_imap(
    payload: ImapConnectRequest,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> EmailConnectionStatus:
    """Validate IMAP credentials, store them, and return the new connection status."""
    del principal
    try:
        await asyncio.to_thread(
            imap_verify_connection,
            payload.host,
            payload.port,
            payload.email,
            payload.password,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await _upsert_setting(session, IMAP_HOST_KEY, payload.host)
    await _upsert_setting(session, IMAP_PORT_KEY, str(payload.port))
    await _upsert_setting(session, IMAP_USERNAME_KEY, payload.email)
    await _upsert_setting(session, IMAP_PASSWORD_KEY, payload.password)
    await _upsert_setting(session, IMAP_FOLDER_KEY, payload.folder)
    logger.info("email.imap.connected", host=payload.host, account=payload.email)

    return EmailConnectionStatus(
        google_connected=bool(await _get_setting(session, GOOGLE_TOKEN_KEY)),
        microsoft_connected=bool(await _get_setting(session, MICROSOFT_TOKEN_KEY)),
        imap_connected=True,
        imap_account=payload.email,
    )


# --------------------------------------------------------------------------- #
# Unified scan endpoint
# --------------------------------------------------------------------------- #

class EmailScanRequest(BaseModel):
    provider: str = "google"   # "google" | "microsoft"
    limit: int = 20


class EmailScanResponse(BaseModel):
    provider: str
    emails_fetched: int
    findings_total: int
    findings: list[FindingRead]


@router.post("/scan", response_model=EmailScanResponse, summary="Fetch emails and run phishing agent")
async def email_scan(
    payload: EmailScanRequest,
    session: SessionDep,
    client: AiEngineDep,
    principal: CurrentPrincipal,
) -> EmailScanResponse:
    """Pull the latest N emails from the connected mailbox and run the phishing agent on each."""
    del principal

    # ---- Fetch raw MIME emails from the provider ----------------------------
    raw_emails: list[str] = []

    if payload.provider == "google":
        token_json = await _get_setting(session, GOOGLE_TOKEN_KEY)
        if not token_json:
            raise HTTPException(status_code=400, detail="Gmail not connected. Go to Settings → Email Integration.")
        token = parse_token(token_json)
        access_token = token.get("access_token", "")

        # Refresh if needed (Google tokens expire after 1h)
        if not access_token:
            client_id = await _get_setting(session, GOOGLE_CLIENT_ID_KEY) or ""
            client_secret = await _get_setting(session, GOOGLE_CLIENT_SECRET_KEY) or ""
            refreshed = await google_refresh_token(token.get("refresh_token", ""), client_id, client_secret)
            token.update(refreshed)
            await _upsert_setting(session, GOOGLE_TOKEN_KEY, format_token(token))
            access_token = token.get("access_token", "")

        try:
            raw_emails = await gmail_fetch_emails(access_token, limit=payload.limit)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=f"Gmail fetch failed: {exc}") from exc

    elif payload.provider == "microsoft":
        token_json = await _get_setting(session, MICROSOFT_TOKEN_KEY)
        if not token_json:
            raise HTTPException(status_code=400, detail="Microsoft not connected. Go to Settings → Email Integration.")
        token = parse_token(token_json)
        access_token = token.get("access_token", "")

        if not access_token:
            client_id = await _get_setting(session, MICROSOFT_CLIENT_ID_KEY) or ""
            client_secret = await _get_setting(session, MICROSOFT_CLIENT_SECRET_KEY) or ""
            tenant_id = await _get_setting(session, MICROSOFT_TENANT_ID_KEY) or "common"
            refreshed = await microsoft_refresh_token(
                token.get("refresh_token", ""), client_id, client_secret, tenant_id
            )
            token.update(refreshed)
            await _upsert_setting(session, MICROSOFT_TOKEN_KEY, format_token(token))
            access_token = token.get("access_token", "")

        try:
            raw_emails = await outlook_fetch_emails(access_token, limit=payload.limit)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=f"Microsoft fetch failed: {exc}") from exc

    elif payload.provider == "imap":
        host = await _get_setting(session, IMAP_HOST_KEY)
        user = await _get_setting(session, IMAP_USERNAME_KEY)
        password = await _get_setting(session, IMAP_PASSWORD_KEY)
        folder = await _get_setting(session, IMAP_FOLDER_KEY) or "INBOX"
        if not host or not user or not password:
            raise HTTPException(status_code=400, detail="No IMAP mailbox connected. Go to Settings → Email Integration.")
        try:
            port = int((await _get_setting(session, IMAP_PORT_KEY)) or "993")
        except ValueError:
            port = 993
        try:
            raw_emails = await asyncio.to_thread(
                imap_fetch_emails, host, port, user, password, folder, payload.limit
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=f"IMAP fetch failed: {exc}") from exc

    else:
        raise HTTPException(status_code=400, detail="Unknown provider. Use 'google', 'microsoft' or 'imap'.")

    logger.info("email.scan.fetched", provider=payload.provider, count=len(raw_emails))

    # A scan of the mailbox is one run: its findings share a run_id so they stay
    # grouped as a single session on the scans page, and it shows up in the
    # recent-scans list on the home page.
    run = RunModel(target=f"email:{payload.provider}", mode="auto")
    session.add(run)
    await session.commit()
    await session.refresh(run)

    # ---- Run phishing agent on each email -----------------------------------
    all_findings: list[FindingRead] = []
    for raw_mime in raw_emails:
        try:
            request = AgentRunRequest(
                source=payload.provider,
                asset=None,
                raw_input=raw_mime,
                background=False,
                persist=True,
                run_id=run.id,
            )
            rows = await run_agent(session, client, AgentKind.phishing, request)
            all_findings.extend(FindingRead.model_validate(row) for row in rows)
        except AiEngineError as exc:
            logger.warning("email.scan.agent_error", error=str(exc))

    run.agent_statuses = {
        "phishing": {"state": "done", "count": len(all_findings)},
        "vulnerability": {"state": "skipped", "count": 0},
        "network": {"state": "skipped", "count": 0},
        "webapp": {"state": "skipped", "count": 0},
    }
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    await session.commit()

    logger.info("email.scan.done", provider=payload.provider, findings=len(all_findings))

    return EmailScanResponse(
        provider=payload.provider,
        emails_fetched=len(raw_emails),
        findings_total=len(all_findings),
        findings=all_findings,
    )
