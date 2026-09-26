"""Async Tor fetcher.

Uses a single shared ``httpx.AsyncClient`` configured with a SOCKS5 proxy. This
replaces the original project's global ``socket.socket`` monkeypatch — the proxy
is scoped to *this client only*, so nothing else in the process is affected, and
concurrent requests are safe (httpx async clients are designed for it).

``.onion`` name resolution is handled by Tor at the SOCKS layer.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass, field

import httpx

from ..logging import get_logger
from ..netguard import guard_request
from ..scope import ScopeError, allows

log = get_logger("fetch")

# Content types we are willing to decode to text. Anything else is treated as a
# binary blob (we keep bytes for hashing but do not attempt ``.text``).
_TEXTUAL = ("text/", "application/json", "application/xml", "application/xhtml")


@dataclass
class FetchResult:
    url: str
    ok: bool
    status: int | None = None
    body: bytes = b""
    text: str | None = None
    content_type: str | None = None
    error: str | None = None
    truncated: bool = False
    final_url: str | None = None
    fetched_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))


class TorFetcher:
    def __init__(
        self,
        socks_host: str,
        socks_port: int,
        *,
        user_agent: str,
        timeout: float = 60.0,
        retries: int = 2,
        max_bytes: int = 5_000_000,
        use_tor: bool = True,
        allowed_hosts: list[str] | None = None,
    ) -> None:
        # use_tor=False fetches directly (no proxy) — for clearnet-only test runs
        # and local demos without a Tor daemon. Leave it on for real crawling.
        proxy = f"socks5://{socks_host}:{socks_port}" if use_tor else None
        # Through Tor, private destinations are refused by Tor itself. Without
        # it the client connects directly, and a seed URL — or any link found on
        # a page — could point at this host's own network. The guard is a
        # request hook so it also covers every redirect hop.
        self.allowed_hosts = allowed_hosts or []

        async def enforce_scope(request):
            if not allows(str(request.url), self.allowed_hosts):
                raise ScopeError("Request or redirect outside allowed hosts")

        hooks = {"request": [enforce_scope] + ([] if use_tor else [guard_request])}
        self._client = httpx.AsyncClient(
            proxy=proxy,
            headers={"User-Agent": user_agent},
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            max_redirects=5,
            event_hooks=hooks,
        )
        self.retries = retries
        self.max_bytes = max_bytes
        self.total_timeout = timeout

    async def fetch(self, url: str) -> FetchResult:
        last_error: str | None = None
        for attempt in range(self.retries + 1):
            try:
                # Bound retained bytes and wall-clock time. Content decompression
                # is performed by httpx; this is not a wire-byte memory guarantee.
                async with asyncio.timeout(self.total_timeout), self._client.stream("GET", url) as resp:
                    ctype = resp.headers.get("content-type", "").lower()
                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    async for chunk in resp.aiter_bytes(chunk_size=16_384):
                        remaining = self.max_bytes - total
                        chunks.append(chunk[:remaining])
                        total += min(len(chunk), remaining)
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    body = b"".join(chunks)[: self.max_bytes]

                textual = any(t in ctype for t in _TEXTUAL) or ctype == ""
                text = None
                if textual:
                    try:
                        text = body.decode(resp.encoding or "utf-8", "ignore")
                    except (LookupError, TypeError):  # bogus charset in header
                        text = body.decode("utf-8", "ignore")
                return FetchResult(
                    url=url,
                    ok=resp.status_code == 200,
                    status=resp.status_code,
                    body=body,
                    text=text,
                    content_type=ctype,
                    truncated=truncated,
                    final_url=str(resp.url),
                )
            except ScopeError:
                raise
            except Exception as exc:  # network errors are expected on the dark web
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
        log.debug("fetch failed url=%s err=%s", url, last_error)
        return FetchResult(url=url, ok=False, error=last_error)

    async def aclose(self) -> None:
        await self._client.aclose()
