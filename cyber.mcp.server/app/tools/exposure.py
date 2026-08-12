"""Is this asset reachable from outside?

Exposure is worth 22 of the 100 prioritisation points in the ai.engine, so it has
to be answered honestly rather than optimistically. Three answers only:

* ``internal``  - a private, loopback or link-local address; provably not routable
                  from the internet.
* ``unknown``   - a hostname, or a public address we have not confirmed is
                  actually reachable. **This is not "internal".** Assuming an
                  unverified asset is safe is how an internet-facing box ends up
                  ranked below a lab machine.
* ``internet``  - a public, globally-routable address.

There is no active reachability probe here. Confirming that a public address
answers from outside would mean scanning from an external vantage point, which
this platform does not have and should not pretend to.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Final, Literal

from app.tools.targets import normalize_target

Exposure = Literal["internet", "internal", "unknown"]

_INTERNAL_SUFFIXES: Final = (".localhost", ".local", ".localdomain", ".internal", ".lan")
_INTERNAL_HOSTNAMES: Final = frozenset({"localhost"})


def classify_exposure(asset: str) -> dict[str, Any]:
    """Classify one asset's network exposure."""
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
        return {
            "asset": target,
            "exposure": "unknown",
            "reason": (
                "A hostname is not resolved here, so its exposure cannot be established. "
                "Treated as unknown rather than internal."
            ),
            "is_ip": False,
        }

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
            "asset": str(address),
            "exposure": "internet",
            "reason": "A globally-routable public address.",
            "is_ip": True,
        }

    return {
        "asset": str(address),
        "exposure": "internal",
        "reason": f"A {detail} address, not routable from the internet.",
        "is_ip": True,
    }
