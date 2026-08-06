"""Email OAuth integration service.

Handles OAuth 2.0 token exchange and MIME email fetching for both
Gmail (Google) and Microsoft 365 (Outlook) providers.

All OAuth secrets and tokens are stored via the settings table.
Tokens are stored as JSON strings under well-known keys.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Setting key constants
# --------------------------------------------------------------------------- #

GOOGLE_CLIENT_ID_KEY = "email_google_client_id"
GOOGLE_CLIENT_SECRET_KEY = "email_google_client_secret"
GOOGLE_TOKEN_KEY = "email_google_token"           # JSON: {access_token, refresh_token, ...}

MICROSOFT_CLIENT_ID_KEY = "email_microsoft_client_id"
MICROSOFT_CLIENT_SECRET_KEY = "email_microsoft_client_secret"
MICROSOFT_TENANT_ID_KEY = "email_microsoft_tenant_id"
MICROSOFT_TOKEN_KEY = "email_microsoft_token"     # JSON: {access_token, refresh_token, ...}

IMAP_HOST_KEY = "email_imap_host"
IMAP_PORT_KEY = "email_imap_port"
IMAP_USERNAME_KEY = "email_imap_username"
IMAP_PASSWORD_KEY = "email_imap_password"
IMAP_FOLDER_KEY = "email_imap_folder"

# --------------------------------------------------------------------------- #
# Google / Gmail
# --------------------------------------------------------------------------- #

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"


def google_auth_url(client_id: str, redirect_uri: str) -> str:
    """Return the Google OAuth consent screen URL."""
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GOOGLE_SCOPES,
        "access_type": "offline",
        "prompt": "consent",
    }
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{GOOGLE_AUTH_URL}?{qs}"


async def google_exchange_code(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an auth code for Google access + refresh tokens."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def google_refresh_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
) -> dict[str, Any]:
    """Refresh an expired Google access token."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "refresh_token",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def gmail_fetch_emails(
    access_token: str,
    limit: int = 20,
    label: str = "INBOX",
) -> list[str]:
    """Return a list of raw MIME email strings from Gmail.

    Args:
        access_token: Valid Google access token with gmail.readonly scope.
        limit: Maximum number of messages to fetch.
        label: Gmail label to read from (default: INBOX).

    Returns:
        List of raw MIME email strings ready for the phishing agent.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    raw_emails: list[str] = []

    async with httpx.AsyncClient(timeout=30) as client:
        # 1. List message IDs (most recent first; no recency/read-state filter so
        #    a normal inbox always yields something to analyse).
        list_resp = await client.get(
            f"{GMAIL_API_BASE}/users/me/messages",
            headers=headers,
            params={"maxResults": limit, "labelIds": label},
        )
        if list_resp.status_code != 200:
            detail = ""
            try:
                err = list_resp.json().get("error", {})
                detail = err.get("message", "") or list_resp.text[:200]
            except Exception:
                detail = list_resp.text[:200]
            raise RuntimeError(
                f"Gmail API request failed ({list_resp.status_code}): {detail}"
            )

        message_ids = [m["id"] for m in list_resp.json().get("messages", [])]
        logger.info("gmail.messages_found", count=len(message_ids))

        # 2. Fetch each message as raw MIME
        for msg_id in message_ids:
            msg_resp = await client.get(
                f"{GMAIL_API_BASE}/users/me/messages/{msg_id}",
                headers=headers,
                params={"format": "raw"},
            )
            if msg_resp.status_code != 200:
                logger.warning("gmail.fetch_failed", msg_id=msg_id, status=msg_resp.status_code)
                continue

            raw_b64 = msg_resp.json().get("raw", "")
            if raw_b64:
                import base64
                try:
                    raw_mime = base64.urlsafe_b64decode(raw_b64 + "==").decode("utf-8", errors="replace")
                    raw_emails.append(raw_mime)
                except Exception as exc:
                    logger.warning("gmail.decode_failed", msg_id=msg_id, error=str(exc))

    return raw_emails


# --------------------------------------------------------------------------- #
# Microsoft / Outlook
# --------------------------------------------------------------------------- #

MS_AUTH_BASE = "https://login.microsoftonline.com"
MS_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
MS_SCOPES = "offline_access Mail.Read"


def microsoft_auth_url(client_id: str, tenant_id: str, redirect_uri: str) -> str:
    """Return the Microsoft OAuth consent screen URL."""
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": MS_SCOPES,
        "response_mode": "query",
    }
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{MS_AUTH_BASE}/{tenant_id}/oauth2/v2.0/authorize?{qs}"


async def microsoft_exchange_code(
    code: str,
    client_id: str,
    client_secret: str,
    tenant_id: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an auth code for Microsoft access + refresh tokens."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{MS_AUTH_BASE}/{tenant_id}/oauth2/v2.0/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "scope": MS_SCOPES,
                "grant_type": "authorization_code",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def microsoft_refresh_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Refresh an expired Microsoft access token."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{MS_AUTH_BASE}/{tenant_id}/oauth2/v2.0/token",
            data={
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": MS_SCOPES,
                "grant_type": "refresh_token",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def outlook_fetch_emails(
    access_token: str,
    limit: int = 20,
) -> list[str]:
    """Return a list of raw MIME email strings from Microsoft 365/Outlook.

    Args:
        access_token: Valid Microsoft Graph access token with Mail.Read scope.
        limit: Maximum number of messages to fetch.

    Returns:
        List of raw MIME email strings ready for the phishing agent.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    raw_emails: list[str] = []

    async with httpx.AsyncClient(timeout=30) as client:
        # 1. List messages from inbox
        list_resp = await client.get(
            f"{MS_GRAPH_BASE}/me/mailFolders/inbox/messages",
            headers=headers,
            params={
                "$top": limit,
                "$select": "id,subject,receivedDateTime",
                "$orderby": "receivedDateTime desc",
            },
        )
        if list_resp.status_code != 200:
            detail = ""
            try:
                err = list_resp.json().get("error", {})
                detail = err.get("message", "") or list_resp.text[:200]
            except Exception:
                detail = list_resp.text[:200]
            raise RuntimeError(
                f"Microsoft Graph request failed ({list_resp.status_code}): {detail}"
            )

        messages = list_resp.json().get("value", [])
        logger.info("outlook.messages_found", count=len(messages))

        # 2. Fetch each message as MIME
        for msg in messages:
            msg_id = msg["id"]
            mime_resp = await client.get(
                f"{MS_GRAPH_BASE}/me/messages/{msg_id}/$value",
                headers={**headers, "Accept": "text/plain"},
            )
            if mime_resp.status_code != 200:
                logger.warning("outlook.fetch_failed", msg_id=msg_id, status=mime_resp.status_code)
                continue
            raw_emails.append(mime_resp.text)

    return raw_emails


# --------------------------------------------------------------------------- #
# IMAP / generic mail servers
# --------------------------------------------------------------------------- #

def imap_verify_connection(
    host: str,
    port: int,
    username: str,
    password: str,
) -> None:
    """Open an IMAPS session to validate credentials.

    Raises:
        RuntimeError: with a user-readable message if the server is
            unreachable, TLS fails, or authentication is rejected.
    """
    import imaplib

    try:
        client = imaplib.IMAP4_SSL(host, port, timeout=15)
    except Exception as exc:
        raise RuntimeError(f"Could not connect to {host}:{port} ({exc})") from exc

    try:
        client.login(username, password.replace(" ", ""))
    except imaplib.IMAP4.error as exc:
        raise RuntimeError(
            f"Login failed for {username} on {host}. Check the address and "
            "app password (an IMAP client password, not your normal password)."
        ) from exc
    finally:
        try:
            client.logout()
        except Exception as exc:
            logger.debug("imap.logout_failed", error=str(exc))


def imap_fetch_emails(
    host: str,
    port: int,
    username: str,
    password: str,
    folder: str = "INBOX",
    limit: int = 20,
) -> list[str]:
    """Fetch raw MIME email strings from an IMAP folder.

    Blocks on network I/O — call via ``asyncio.to_thread``.

    Raises:
        RuntimeError: if the server is unreachable, login fails, or the
            selected folder cannot be opened.
    """
    import imaplib

    try:
        client = imaplib.IMAP4_SSL(host, port, timeout=20)
    except Exception as exc:
        raise RuntimeError(f"Could not connect to {host}:{port} ({exc})") from exc

    raw_emails: list[str] = []
    try:
        try:
            client.login(username, password.replace(" ", ""))
        except imaplib.IMAP4.error as exc:
            raise RuntimeError(
                f"Login failed for {username} on {host}. Check the address and "
                "app password (an IMAP client password, not your normal password)."
            ) from exc

        typ, data = client.select(folder, readonly=True)
        if typ != "OK":
            raise RuntimeError(
                f"Could not open folder '{folder}' on {host}. It may not exist "
                "or the account may not have IMAP enabled."
            )

        typ, data = client.search(None, "ALL")
        if typ != "OK" or not data or not data[0]:
            logger.info("imap.messages_found", host=host, count=0)
            return []

        ids = [int(i) for i in data[0].split()]
        logger.info("imap.messages_found", host=host, count=len(ids))

        for msg_id in ids[-limit:]:
            try:
                typ, msg_data = client.fetch(str(msg_id), "(RFC822)")
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                payload = msg_data[0][1]
                if isinstance(payload, bytes):
                    raw_emails.append(payload.decode("utf-8", errors="replace"))
            except (imaplib.IMAP4.error, IndexError, KeyError) as exc:
                logger.warning("imap.fetch_failed", msg_id=msg_id, error=str(exc))
    finally:
        try:
            client.logout()
        except Exception as exc:
            logger.debug("imap.logout_failed", error=str(exc))

    return raw_emails


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def parse_token(token_json: str) -> dict[str, Any]:
    """Parse a stored token JSON string."""
    try:
        return json.loads(token_json)
    except (json.JSONDecodeError, TypeError):
        return {}


def format_token(token_data: dict[str, Any]) -> str:
    """Serialise a token dict for storage in the settings table."""
    return json.dumps(token_data)
