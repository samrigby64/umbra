"""Tests for the outbound-request guard.

The server makes HTTP requests to addresses other people choose: webhook URLs,
and (without Tor) crawl seeds and discovered links. Every case here is a way an
attacker would try to point one of those at the server's own network.
"""

import httpx
import pytest

from umbra import netguard
from umbra.netguard import UnsafeDestination, check_url, is_public_address


def test_address_classification():
    for address in (
        "127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5",
        "169.254.169.254",        # cloud metadata
        "::1", "fd00:ec2::254",   # v6 loopback, AWS IMDS v6
        "::ffff:10.0.0.1",        # v4-mapped v6: the private range in disguise
        "0.0.0.0", "224.0.0.1", "fe80::1%eth0",
    ):
        assert not is_public_address(address), address
    for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert is_public_address(address), address
    assert not is_public_address("not-an-address")


async def test_literal_private_and_metadata_addresses_are_refused():
    for url in (
        "http://127.0.0.1:8000/admin/crawl",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:9050/",
        "http://10.0.0.5/",
        "http://[::ffff:192.168.1.1]/",
    ):
        with pytest.raises(UnsafeDestination):
            await check_url(url)


async def test_non_http_schemes_and_local_names_are_refused():
    for url in (
        "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/",
        "http://localhost/", "http://box.internal/", "http://printer.local/",
        "http://abc.onion/",      # webhooks never go through Tor; this can't be right
        "http:///nohost",
    ):
        with pytest.raises(UnsafeDestination):
            await check_url(url)


async def test_a_name_with_any_private_record_is_refused(monkeypatch):
    """One public and one private A record must fail, whichever the resolver
    happens to return first."""
    async def fake(host):
        return ["93.184.216.34", "10.0.0.1"]

    monkeypatch.setattr(netguard, "resolve", fake)
    with pytest.raises(UnsafeDestination):
        await check_url("https://hooks.example.com/x")


async def test_public_resolution_passes(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "resolve", fake)
    await check_url("https://hooks.example.com/x")  # no exception


async def test_unresolvable_names_are_refused(monkeypatch):
    """Can't verify, don't send."""
    async def fake(host):
        raise UnsafeDestination("nxdomain")

    monkeypatch.setattr(netguard, "resolve", fake)
    with pytest.raises(UnsafeDestination):
        await check_url("https://does-not-exist.example/")


async def test_hook_refuses_a_redirect_into_the_private_network(monkeypatch):
    """The standard bypass for a check on the starting URL: a public host that
    302s to loopback. The guard is a request hook precisely so it runs on the
    redirected request too."""
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "resolve", fake)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "public.example.com":
            return httpx.Response(302, headers={"location": "http://127.0.0.1:9050/"})
        return httpx.Response(200, text="must never be reached")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        event_hooks={"request": [netguard.guard_request]},
    ) as client:
        with pytest.raises(UnsafeDestination):
            await client.get("http://public.example.com/")
