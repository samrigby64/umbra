"""Outbound-request guard: the server must never be talked into calling home.

Two things here make HTTP requests to addresses that somebody else chose. Alert
delivery POSTs to a watchlist's webhook URL, and the crawler fetches seed URLs
and every link it discovers on a page. Both have the classic server-side request
forgery shape: an attacker supplies an address, the server connects to it from
*inside* the deployment's network, and either the response or the request body
leaks something the server could see and the attacker could not. A webhook
pointed at a cloud metadata endpoint or a loopback admin port is the textbook
case — and the request body here is dark-web intelligence, so it doubles as an
exfiltration channel.

With Tor in the path the crawler is already safe: Tor refuses to connect to
private and loopback destinations. Without it (``use_tor=False``, meant for
clearnet test runs) the client resolves and connects directly, and needs this.
Webhooks never go through Tor, so they always need it.

Installed as an ``httpx`` request hook rather than a one-off check before the
first request, so it also fires on every redirect: a public URL that 302s to
``http://169.254.169.254/`` is the standard way past a check that only looks at
the starting address.

**Residual risk, stated rather than hidden:** the hostname is resolved here and
again by the HTTP client a moment later. A DNS server that answers differently
on consecutive lookups (rebinding) can slip through that window. Pinning the
connection to the address that was checked would close it, at the cost of
re-implementing part of the client; for an admin-only surface that is a
proportionate trade, and it is documented so the decision can be revisited.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import httpx


class UnsafeDestination(ValueError):
    """The URL points somewhere this server must not connect to."""


_ALLOWED_SCHEMES = ("http", "https")

# Names that never denote a public host, whatever they resolve to.
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".onion")
_BLOCKED_NAMES = frozenset({"localhost", "localhost.localdomain"})


def is_public_address(value: str) -> bool:
    """True if ``value`` is a routable public IP address."""
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])  # drop any v6 scope id
    except ValueError:
        return False
    # An IPv4-mapped IPv6 address (::ffff:10.0.0.1) is the v4 address in
    # disguise; judge the thing it maps to, or the private ranges are one
    # notation away from slipping past.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


async def resolve(host: str) -> list[str]:
    """Every address ``host`` currently resolves to.

    All of them are checked, not just the first: a name with one public and one
    private record would otherwise pass or fail depending on resolver ordering.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeDestination(f"cannot resolve {host!r}: {exc}") from None
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeDestination(f"{host!r} resolved to nothing")
    return addresses


async def check_url(url: str) -> None:
    """Raise :class:`UnsafeDestination` unless ``url`` points at a public host."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeDestination(f"scheme {parsed.scheme!r} not allowed")
    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeDestination("no host in URL")
    if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeDestination(f"{host!r} is not a public host")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        candidates = await resolve(host)
    else:
        candidates = [host]

    for address in candidates:
        if not is_public_address(address):
            raise UnsafeDestination(f"{host!r} resolves to non-public address {address}")


async def guard_request(request: httpx.Request) -> None:
    """``httpx`` event hook: refuse the request if its destination is not public."""
    await check_url(str(request.url))
