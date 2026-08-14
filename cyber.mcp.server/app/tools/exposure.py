"""Is this asset reachable from outside?

Exposure is worth 22 of the 100 prioritisation points in the ai.engine, so it has
to be answered honestly rather than optimistically. Three answers only:

* ``internal``  - a private, loopback or link-local address; provably not routable
                  from the internet.
* ``unknown``   - a name that does not resolve, or a public address we have not
                  confirmed is actually reachable. **This is not "internal".**
                  Assuming an unverified asset is safe is how an internet-facing
                  box ends up ranked below a lab machine.
* ``internet``  - a public, globally-routable address.

Hostnames are resolved. They did not used to be, and the cost was silent and
one-directional: an asset named ``server.client.com`` scored ``unknown`` while the
same host named by address scored ``internet``, so naming a host the way a client
actually refers to it cost it 22 points of priority against an identical host
entered as an IP.

There is still no active reachability probe. Confirming that a public address
answers from outside would mean scanning from an external vantage point, which
this platform does not have and should not pretend to.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Final, Literal

from app.tools.targets import normalize_target, resolve_addresses

Exposure = Literal["internet", "internal", "unknown"]

_INTERNAL_SUFFIXES: Final = (".localhost", ".local", ".localdomain", ".internal", ".lan")
_INTERNAL_HOSTNAMES: Final = frozenset({"localhost"})


async def classify_exposure(asset: str) -> dict[str, Any]:
    """Classify one asset's network exposure, resolving it if it is a name."""
    target = normalize_target(asset)
    if not target:
        return {
            "asset": asset,
            "exposure": "unknown",
            "reason": "No asset was supplied.",
            "is_ip": False,
        }

    lowered = target.lower()
    if lowered in _INTERNAL_HOSTNAMES or lowered.endswith(_INTERNAL_SUFFIXES):
        return {
            "asset": target,
            "exposure": "internal",
            "reason": "The name is in a reserved or private-use namespace.",
            "is_ip": False,
        }

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return await _classify_hostname(target)

    # str(address), not the raw text: an address is its own canonical name, and
    # this keeps the answer byte-identical to what it was before names resolved.
    return _classify_address(str(address), address, resolved_from="")


async def _classify_hostname(host: str) -> dict[str, Any]:
    """Resolve a name and classify what it points at.

    A name that resolves to several addresses is classified by the most exposed of
    them: a host reachable from the internet on any of its addresses is
    internet-exposed, whatever else it also answers on.
    """
    try:
        addresses = await resolve_addresses(host)
    except OSError as err:
        return {
            "asset": host,
            "exposure": "unknown",
            "reason": (
                f"{host} did not resolve ({err}), so its exposure cannot be "
                "established. Treated as unknown rather than internal."
            ),
            "is_ip": False,
        }

    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_address in addresses:
        try:
            parsed.append(ipaddress.ip_address(raw_address))
        except ValueError:
            continue

    if not parsed:
        return {
            "asset": host,
            "exposure": "unknown",
            "reason": (
                f"{host} resolved to no usable address, so its exposure cannot be "
                "established. Treated as unknown rather than internal."
            ),
            "is_ip": False,
        }

    public = next((address for address in parsed if _is_public(address)), None)
    return _classify_address(host, public or parsed[0], resolved_from=host)


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
        or address.is_multicast
    )


def _classify_address(
    asset: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    resolved_from: str,
) -> dict[str, Any]:
    """Classify one literal address.

    ``asset`` is what the caller named it, which is kept as the answer's identity so
    a finding reads back as the host the analyst asked about rather than as an
    address they would have to look up.
    """
    via = f" ({resolved_from} resolves to {address})" if resolved_from else ""

    if address.is_loopback:
        detail = "loopback"
    elif address.is_link_local:
        detail = "link-local"
    elif address.is_private:
        detail = "private (RFC1918 or equivalent)"
    elif address.is_reserved or address.is_multicast:
        detail = "reserved or multicast"
    else:
        return {
            "asset": asset,
            "exposure": "internet",
            "reason": f"A globally-routable public address{via}.",
            "is_ip": not resolved_from,
        }

    return {
        "asset": asset,
        "exposure": "internal",
        "reason": f"A {detail} address, not routable from the internet{via}.",
        "is_ip": not resolved_from,
    }
