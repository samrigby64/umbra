"""A populated, entirely synthetic Umbra instance: explore the GUI without Tor.

Runs the *real* pipeline (crawler, extractors, timeline, run health, actor
resolution, watchlists) over a fictional site graph served from memory. Nothing
touches the network. Two collection passes are recorded, and between them one
shop goes dark and a vendor rotates their PGP key, so the timeline, service
status and alerts have genuine transitions to show.

    python scripts/demo_lab.py            # then open http://127.0.0.1:8767/

Every host, handle, wallet, key and address here is fictional. The wallets are
well-known documentation examples; the onion names are visibly synthetic.
Collection is disabled in this instance (preview mode).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import sqlalchemy as sa
import uvicorn

from umbra.alerting import evaluate_watchlists
from umbra.api.app import create_app
from umbra.compliance.policy import CompliancePolicy
from umbra.config import Settings
from umbra.crawl.crawler import Crawler
from umbra.crawl.scorer import KeywordScorer, StructuralScorer
from umbra.db import Database
from umbra.factory import build_enrichers
from umbra.fetch.client import FetchResult
from umbra.intel.embeddings import build_embedder
from umbra.intel.entities import resolve_actors
from umbra.models import Page, Watchlist
from umbra.runs import record_run

PORT = int(os.environ.get("UMBRA_DEMO_PORT", "8767"))


def onion(label: str) -> str:
    """A 56-character v3-shaped onion name that is obviously not real."""
    return (label + "synthdemo" * 8)[:56] + ".onion"


ALPHA, BRAVO, CHARLIE, DELTA, ECHO = (
    onion(x) for x in ("alphamarket", "bravoforum", "charliepaste", "deltadirectory", "echoshop")
)

FP_OLD = "1111 2222 3333 4444 5555  6666 7777 8888 9999 AAAA"
FP_NEW = "BBBB CCCC DDDD EEEE FFFF  1234 5678 9ABC DEF0 1234"


def page(title: str, body: str) -> str:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


def graph(pass_no: int) -> dict[str, str]:
    """The fictional dark web, as it looks on a given pass."""
    vendor_keys = f"Key fingerprint = {FP_OLD}"
    if pass_no == 2:
        vendor_keys += f"<br>New signing key from this month: Key fingerprint = {FP_NEW}"
    price = "$95" if pass_no == 1 else "$110"
    g = {
        f"http://{DELTA}/": page("Delta Directory [synthetic demo]", f"""
            <h1>Link directory</h1>
            <a href="http://{ALPHA}/">Alpha Market</a>
            <a href="http://{BRAVO}/">Bravo Forum</a>
            <a href="http://{CHARLIE}/">Charlie Paste</a>
            <a href="http://{ECHO}/">Echo Shop</a>"""),
        f"http://{ALPHA}/": page("Alpha Market [synthetic demo]", """
            <h1>Alpha Market</h1>
            <a href="/vendor/examplevendor">Top vendor</a>
            <a href="/listings?cat=cards">Cards</a>
            <a href="/login.php">Login</a>"""),
        f"http://{ALPHA}/vendor/examplevendor": page("Vendor profile [synthetic demo]", f"""
            <p>Vendor: ExampleVendor</p>
            <p>{vendor_keys}</p>
            <p>Payments: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2</p>
            <p>Contact test.vendor@protonmail.com for bulk orders.</p>"""),
        f"http://{ALPHA}/listings?cat=cards": page("Cards [synthetic demo]", f"""
            <table>
              <tr><td>Card data bundle (x10, synthetic)</td><td>{price}</td></tr>
              <tr><td>Card data bundle (x50, synthetic)</td><td>$390</td></tr>
              <tr><td>Bank login (synthetic)</td><td>$140</td></tr>
            </table>"""),
        f"http://{ALPHA}/login.php": page("Login", "<form>username password</form>"),
        f"http://{BRAVO}/": page("Bravo Forum [synthetic demo]", """
            <a href="/thread/1042">Trusted sellers thread</a>"""),
        f"http://{BRAVO}/thread/1042": page("Trusted sellers [synthetic demo]", """
            <p>ExampleVendor delivered again, paid to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.</p>
            <p>Sold by: SecondSeller - wallet 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy</p>
            <p>Jabber: secondseller@exploit.im</p>"""),
        f"http://{CHARLIE}/": page("Charlie Paste [synthetic demo]", """
            <pre>combo dump (synthetic)
            j.smith@example-corp.test:Winter2026!
            a.jones@example-corp.test:Password1
            ops@example-corp.test:letmein99</pre>"""),
        f"http://{ECHO}/": page("Echo Shop [synthetic demo]", """
            <p>Sold by: EchoTrader</p>
            <p>Payments to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT</p>
            <table><tr><td>Phishing kit (synthetic)</td><td>$60</td></tr></table>"""),
    }
    if pass_no == 2:
        del g[f"http://{ECHO}/"]  # the shop went dark between passes
    return g


class MemoryFetcher:
    """Serves the fictional graph. No sockets are opened."""

    def __init__(self) -> None:
        self.graph = graph(1)

    async def fetch(self, url: str) -> FetchResult:
        html = self.graph.get(url)
        if html is None:
            return FetchResult(url=url, ok=False, error="ConnectError: host unreachable (synthetic)")
        body = html.encode()
        return FetchResult(url=url, ok=True, status=200, body=body, text=html,
                           content_type="text/html", final_url=url)

    async def aclose(self) -> None:
        pass


def demo_settings(database: Path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{database.as_posix()}",
        use_tor=False, preview_mode=True, embedder_kind="hashing", embedding_dim=256,
        max_depth=3, max_pages=100, max_workers=2, recrawl_interval_s=3600,
    )


async def build(settings: Settings) -> None:
    db = Database(settings.database_url)
    await db.create_all()
    fetcher = MemoryFetcher()
    crawler = Crawler(
        settings, db, fetcher=fetcher,
        scorer=StructuralScorer(KeywordScorer([])),
        policy=CompliancePolicy(store_html=True),
        enrichers=build_enrichers(settings),
        embedder=build_embedder(settings),
    )

    async def one_pass() -> None:
        async with record_run(db, trigger="worker") as run:
            stats = await crawler.run([f"http://{DELTA}/"])
            run.pages_crawled = stats["crawled"]
            run.pages_dead = stats["dead"]
            run.iocs_found = stats["iocs"]
            run.actors = (await resolve_actors(db))["actors"]

    await one_pass()

    # Time passes: everything comes due, and the world changes.
    fetcher.graph = graph(2)
    async with db.session() as s:
        await s.execute(
            sa.update(Page).where(Page.status == "crawled")
            .values(next_crawl_at=sa.func.datetime("now", "-1 second"))
        )
        s.add_all([
            Watchlist(name="Anything notable", kind="event", value="notable"),
            Watchlist(name="Our domain in a dump", kind="keyword", value="example-corp.test"),
        ])
        await s.commit()
    await one_pass()
    await evaluate_watchlists(db)
    await db.dispose()


def main() -> None:
    database = Path(tempfile.gettempdir()) / "umbra-demo-lab.db"
    for suffix in ("", "-wal", "-shm"):
        Path(f"{database}{suffix}").unlink(missing_ok=True)  # always start fresh
    settings = demo_settings(database)
    asyncio.run(build(settings))
    print(f"Synthetic demo ready: http://127.0.0.1:{PORT}/  (collection disabled)", flush=True)
    uvicorn.run(create_app(settings), host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
