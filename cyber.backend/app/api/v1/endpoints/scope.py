"""Scan scope endpoints.

Which hosts this platform may scan, managed from the UI instead of from a config
file. The MCP server reads ``GET /scan-scope/networks`` at scan time and unions
what it finds with its own static allowlist.

Three decisions worth knowing before changing anything here:

**A hostname is resolved on the way in, and the addresses are what get stored.**
An operator types the name they know their server by; scope is recorded as the
address it points at. Storing the name would mean whoever controls DNS decides
what this platform scans, which is exactly what the target policy in the MCP
server exists to prevent.

**Revocation is a flag, not a delete.** "Who authorised this scan" has to survive
the authorisation being withdrawn, and a deleted row cannot answer it.

**The networks endpoint is internal-key only, and returns only networks.** The
scanner needs addresses; it has no use for who attested to them, so it is not
given them.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import uuid
from typing import Annotated

from cyber_contracts import (
    ScanScopeCreate,
    ScanScopeEntry,
    ScanScopeList,
    ScanScopeNetworks,
    normalize_scope_target,
)
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import SessionDep
from app.core.logging import get_logger
from app.core.security import CurrentPrincipal, InternalKeyGuard
from app.models.scope import ScanScope

logger = get_logger(__name__)

router = APIRouter(prefix="/scan-scope", tags=["scan-scope"])

# A name that resolves to more addresses than this is refused rather than
# authorising all of them: that shape is a CDN or a load balancer, and scanning
# it is not what the operator meant.
_MAX_RESOLVED_ADDRESSES = 8


def _to_entry(row: ScanScope) -> ScanScopeEntry:
    return ScanScopeEntry(
        id=str(row.id),
        network=row.network,
        requested=row.requested,
        label=row.label,
        authorized_by=row.authorized_by,
        note=row.note,
        active=row.active,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _resolve(host: str) -> list[str]:
    """Every IPv4/IPv6 address ``host`` currently resolves to."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def _networks_for(target: str) -> tuple[list[str], str]:
    """Turn one submitted target into the networks to store.

    Returns ``(networks, requested)``, where ``requested`` is the original text
    when a name was resolved and empty when an address was given directly.
    """
    try:
        return [str(normalize_scope_target(target))], ""
    except ValueError as address_error:
        # Not an address or CIDR. It may still be a resolvable hostname; if it is
        # not, the address-shaped complaint is the more useful of the two, so it
        # is what gets raised when resolution also fails.
        if "not an IP address" not in str(address_error):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(address_error),
            ) from address_error

    try:
        addresses = await _resolve(target)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"{target!r} is neither an IP address or CIDR range, nor a name that "
                f"resolves ({exc}). Check the spelling, or enter the address directly."
            ),
        ) from exc

    if not addresses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{target!r} resolved to no addresses.",
        )
    if len(addresses) > _MAX_RESOLVED_ADDRESSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"{target!r} resolves to {len(addresses)} addresses. That is a load "
                "balancer or a CDN rather than a single server; add the specific "
                "addresses you own instead."
            ),
        )

    networks: list[str] = []
    for address in addresses:
        try:
            networks.append(str(normalize_scope_target(address)))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{target!r} resolves to {address}, which cannot be added: {exc}",
            ) from exc
    return networks, target


@router.get("", response_model=ScanScopeList, summary="List authorised scan scope")
async def list_scope(
    session: SessionDep,
    principal: CurrentPrincipal,
    include_revoked: Annotated[bool, Query()] = False,
) -> ScanScopeList:
    """Every range this platform may scan, newest first."""
    del principal
    statement = select(ScanScope).order_by(ScanScope.created_at.desc())
    if not include_revoked:
        statement = statement.where(ScanScope.active.is_(True))
    rows = (await session.execute(statement)).scalars().all()
    return ScanScopeList(items=[_to_entry(row) for row in rows], total=len(rows))


@router.post(
    "",
    response_model=ScanScopeList,
    status_code=status.HTTP_201_CREATED,
    summary="Authorise scanning of a host or range",
)
async def add_scope(
    payload: ScanScopeCreate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> ScanScopeList:
    """Add a host or range to scope.

    A hostname produces one entry per address it resolves to, so each can be
    revoked on its own. Re-adding a range that is already present updates it and
    reinstates it rather than failing - the operator's intent is the same either
    way, and a unique constraint violation is not a useful answer to it.
    """
    del principal
    networks, requested = await _networks_for(payload.target)

    entries: list[ScanScope] = []
    for network in networks:
        existing = (
            await session.execute(select(ScanScope).where(ScanScope.network == network))
        ).scalar_one_or_none()
        if existing is not None:
            existing.requested = requested or existing.requested
            existing.label = payload.label or existing.label
            existing.authorized_by = payload.authorized_by
            existing.note = payload.note or existing.note
            existing.active = True
            entries.append(existing)
            continue

        row = ScanScope(
            network=network,
            requested=requested,
            label=payload.label,
            authorized_by=payload.authorized_by,
            note=payload.note,
            active=True,
        )
        session.add(row)
        entries.append(row)

    await session.commit()
    for row in entries:
        await session.refresh(row)

    logger.info(
        "scope.added",
        networks=[row.network for row in entries],
        requested=requested or payload.target,
        authorized_by=payload.authorized_by,
    )
    return ScanScopeList(items=[_to_entry(row) for row in entries], total=len(entries))


@router.delete(
    "/{scope_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an authorisation",
)
async def revoke_scope(
    scope_id: uuid.UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> None:
    """Revoke one entry. The row is kept, deactivated, so the record survives."""
    del principal
    row = (
        await session.execute(select(ScanScope).where(ScanScope.id == scope_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No such scope entry."
        )

    row.active = False
    await session.commit()
    logger.info("scope.revoked", network=row.network)


@router.get(
    "/networks",
    response_model=ScanScopeNetworks,
    dependencies=[InternalKeyGuard],
    summary="Active scope, for the scanner",
)
async def scope_networks(session: SessionDep) -> ScanScopeNetworks:
    """The active networks, and nothing else.

    Read by the MCP server before every scan. Entries that no longer parse are
    dropped rather than raising: one bad row must not take the whole allowlist
    with it, and dropping narrows scope, which fails in the safe direction.
    """
    rows = (
        await session.execute(select(ScanScope.network).where(ScanScope.active.is_(True)))
    ).scalars().all()

    networks: list[str] = []
    for network in rows:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            logger.warning("scope.unreadable_entry", network=network)
            continue
        networks.append(network)
    return ScanScopeNetworks(networks=networks)
