"""Scan scope: what this platform is authorised to scan.

Split deliberately. The validation rules are pure and run everywhere, because
they are the ones that decide whether a mistyped prefix authorises a subnet or
the internet. The round trip is DB-backed and gated like every other such test.
"""

from __future__ import annotations

import pytest
from cyber_contracts import INTERNAL_KEY_HEADER, MAX_SCOPE_ADDRESSES, normalize_scope_target
from httpx import AsyncClient

from app.core.config import get_settings
from tests.conftest import requires_database


def _internal_headers() -> dict[str, str]:
    """The header the MCP server presents when reading scope.

    Sent explicitly rather than by a fixture, because this is the one endpoint
    here that is service-to-service: the browser-facing routes must keep working
    without it, and a blanket fixture would hide it if that ever changed.
    """
    key = get_settings().internal_key
    return {INTERNAL_KEY_HEADER: key} if key else {}

# ---------------------------------------------------------------------------
# Validation - no database, no network.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("198.51.100.10", "198.51.100.10/32"),
        ("  198.51.100.10  ", "198.51.100.10/32"),
        ("203.0.113.0/24", "203.0.113.0/24"),
        # A host bit set with a prefix is normalised rather than refused: the
        # operator meant the network, and strict=True would reject "10.0.0.5/24".
        ("10.0.0.5/24", "10.0.0.0/24"),
        ("2001:db8::1", "2001:db8::1/128"),
    ],
)
def test_an_address_or_range_becomes_one_canonical_network(raw: str, expected: str) -> None:
    assert str(normalize_scope_target(raw)) == expected


@pytest.mark.parametrize(
    ("raw", "because"),
    [
        ("0.0.0.0/0", "more than"),
        ("10.0.0.0/8", "more than"),
        ("::/0", "more than"),
        ("169.254.169.254", "never be added"),
        ("169.254.0.0/16", "never be added"),
        ("224.0.0.1", "never be added"),
        ("", "No target"),
        ("nonsense", "not an IP address"),
        ("http://example.com", "not an IP address"),
    ],
)
def test_dangerous_or_unreadable_entries_are_refused(raw: str, because: str) -> None:
    """Each of these would otherwise authorise something nobody intended."""
    with pytest.raises(ValueError, match=because):
        normalize_scope_target(raw)


def test_the_cap_is_a_sixteen_bit_network() -> None:
    """A /16 is allowed, a /15 is not - so the boundary is asserted, not assumed."""
    assert str(normalize_scope_target("10.1.0.0/16")) == "10.1.0.0/16"
    with pytest.raises(ValueError, match="more than"):
        normalize_scope_target("10.0.0.0/15")
    assert MAX_SCOPE_ADDRESSES == 65536


def test_the_metadata_endpoint_can_never_be_authorised() -> None:
    """169.254.169.254 reads this platform's own cloud credentials.

    No client authorisation covers that, so it is refused at the contract rather
    than left to whoever fills in the form.
    """
    with pytest.raises(ValueError, match="metadata"):
        normalize_scope_target("169.254.169.254/32")


# ---------------------------------------------------------------------------
# The API round trip.
# ---------------------------------------------------------------------------
#
# Every address below is from a documentation range (RFC 5737 / RFC 3849), never a
# real one. These tests run against the developer's own PostgreSQL, and `network` is
# unique: a test that writes a genuine address does not create a throwaway row, it
# takes over the operator's real authorisation and then revokes it. That happened
# once - the suite went green and the next live scan was refused as out of scope.

@requires_database
async def test_scope_lifecycle(client: AsyncClient) -> None:
    created = await client.post(
        "/scan-scope",
        json={
            "target": "198.51.100.10",
            "label": "client web server",
            "authorized_by": "rhodrick@takenolab.org",
            "note": "owned by us; authorised for testing",
        },
    )
    assert created.status_code == 201, created.text
    entry = created.json()["items"][0]
    assert entry["network"] == "198.51.100.10/32"
    assert entry["active"] is True
    scope_id = entry["id"]

    # The scanner's view: networks only, no attestation details.
    networks = await client.get("/scan-scope/networks", headers=_internal_headers())
    assert networks.status_code == 200
    assert "198.51.100.10/32" in networks.json()["networks"]

    listed = await client.get("/scan-scope")
    assert any(item["id"] == scope_id for item in listed.json()["items"])

    revoked = await client.delete(f"/scan-scope/{scope_id}")
    assert revoked.status_code == 204

    # Revocation takes the range out of the scanner's view immediately...
    after = await client.get("/scan-scope/networks", headers=_internal_headers())
    assert "198.51.100.10/32" not in after.json()["networks"]

    # ...but the record of who authorised it survives.
    history = await client.get("/scan-scope?include_revoked=true")
    revoked_entry = next(i for i in history.json()["items"] if i["id"] == scope_id)
    assert revoked_entry["active"] is False
    assert revoked_entry["authorized_by"] == "rhodrick@takenolab.org"

    await client.delete(f"/scan-scope/{scope_id}")


@requires_database
async def test_re_adding_a_range_reinstates_it_rather_than_failing(
    client: AsyncClient,
) -> None:
    """A unique-constraint 500 is not a useful answer to "authorise this again"."""
    payload = {"target": "203.0.113.7", "authorized_by": "ops"}

    first = await client.post("/scan-scope", json=payload)
    assert first.status_code == 201
    scope_id = first.json()["items"][0]["id"]
    await client.delete(f"/scan-scope/{scope_id}")

    again = await client.post("/scan-scope", json=payload)
    assert again.status_code == 201
    assert again.json()["items"][0]["id"] == scope_id, "the same row, reinstated"
    assert again.json()["items"][0]["active"] is True

    await client.delete(f"/scan-scope/{scope_id}")


@requires_database
async def test_a_refused_range_never_reaches_the_table(client: AsyncClient) -> None:
    response = await client.post(
        "/scan-scope", json={"target": "0.0.0.0/0", "authorized_by": "ops"}
    )

    assert response.status_code == 422
    assert "more than" in response.json()["detail"]


@requires_database
async def test_an_unresolvable_name_is_rejected_with_both_reasons(
    client: AsyncClient,
) -> None:
    """The message has to cover the likely mistake: a typo in either shape."""
    response = await client.post(
        "/scan-scope",
        json={"target": "no-such-host.invalid", "authorized_by": "ops"},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "neither an IP address or CIDR range" in detail
    assert "nor a name that resolves" in detail


@requires_database
async def test_authorized_by_is_required(client: AsyncClient) -> None:
    """Scope is an attestation; an unattributed one is not worth storing."""
    response = await client.post("/scan-scope", json={"target": "203.0.113.9"})

    assert response.status_code == 422
