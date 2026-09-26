"""End-to-end crawl loop test with a fake fetcher (no Tor required).

Drives the full pipeline against a canned link graph: DB-backed frontier ->
fetch -> compliance -> parse -> persist -> IOC enrich -> embed -> discover ->
terminate. Also asserts resumability and semantic search over the results.
"""

import re

import sqlalchemy as sa

from umbra.compliance.policy import CompliancePolicy
from umbra.config import Settings
from umbra.crawl.crawler import Crawler
from umbra.crawl.scorer import KeywordScorer
from umbra.db import Database
from umbra.enrich.ioc import IocExtractor
from umbra.fetch.client import FetchResult
from umbra.intel.embeddings import build_embedder, search
from umbra.models import STATUS_BLOCKED, STATUS_DEAD, Embedding, Ioc, Page

SEED = "http://seed.onion/"
GRAPH = {
    SEED: """<html><head><title>Seed</title></head><body>
        <a href="/a">Page A</a>
        <a href="/b">Page B</a>
        <a href="http://other.onion/">Other site</a>
        <a href="https://clearnet.example/x">Clearnet (should be skipped)</a>
    </body></html>""",
    "http://seed.onion/a": """<html><title>A</title><body>
        Donate BTC 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 to the vendor market.
        <a href="/b">back to B</a></body></html>""",
    "http://seed.onion/b": "<html><title>B</title><body>a quiet dead end page</body></html>",
    "http://other.onion/": "<html><title>Other</title><body>hello from another host</body></html>",
}


class FakeFetcher:
    def __init__(self, graph):
        self.graph = graph

    async def fetch(self, url):
        html = self.graph.get(url)
        if html is None:
            return FetchResult(url=url, ok=False, status=404, error="not found")
        return FetchResult(
            url=url, ok=True, status=200, body=html.encode(),
            text=html, content_type="text/html",
        )

    async def aclose(self):
        pass


def _make(tmp_path):
    settings = Settings()
    settings.max_workers = 4
    settings.max_pages = 50
    settings.max_depth = 3
    settings.allow_clearnet = False
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'crawl.db'}")
    crawler = Crawler(
        settings, db,
        fetcher=FakeFetcher(GRAPH),
        scorer=KeywordScorer([]),
        policy=CompliancePolicy(),
        enrichers=[IocExtractor()],
        embedder=build_embedder(settings),
    )
    return settings, db, crawler


async def test_reused_crawler_does_not_exhaust_its_budget_permanently(tmp_path):
    """The long-running worker reuses one Crawler for every pass. If per-run
    counters aren't reset, max_pages becomes a lifetime cap: pass 1 spends it and
    every later pass exits before fetching anything — silently, because the
    cumulative stats keep reporting pass 1's totals as though work happened.

    Observed live: a worker logged 'crawled: 500' identically on consecutive
    passes, five minutes apart, with the database completely unchanged.
    """
    settings, db, crawler = _make(tmp_path)
    # One worker so the budget is exact: max_pages is a soft limit that can
    # overshoot by up to (workers - 1), since workers claim before it is checked.
    settings.max_workers = 1
    settings.max_pages = 2  # deliberately smaller than the 4-page graph
    await db.create_all()

    first = await crawler.run([SEED])
    assert first["crawled"] == 2  # budget spent

    second = await crawler.run([SEED])
    assert second["crawled"] > 0, "second pass crawled nothing — budget leaked across runs"
    assert second["crawled"] <= 2  # and it is still a per-pass budget

    async with db.session() as s:
        crawled = (
            await s.execute(
                sa.select(sa.func.count()).select_from(Page).where(Page.status == "crawled")
            )
        ).scalar()
    assert crawled > 2  # the frontier genuinely advanced
    await db.dispose()


async def test_stop_request_does_not_disable_the_crawler_forever(tmp_path):
    """A stop ends the crawl it was issued against, and only that one. Left
    sticky, the worker would wind down once and never crawl again."""
    settings, db, crawler = _make(tmp_path)
    await db.create_all()
    crawler._stop_requested = True  # as left behind by a stopped crawl

    assert (await crawler.run([SEED]))["crawled"] > 0
    await db.dispose()


async def test_full_crawl_and_resume(tmp_path):
    settings, db, crawler = _make(tmp_path)
    await db.create_all()

    stats = await crawler.run([SEED])
    assert stats["crawled"] == 4          # all four onion pages
    assert stats["changed"] == 4          # first crawl => all new content
    assert stats["iocs"] >= 1             # the BTC address on /a

    async with db.session() as s:
        urls = set((await s.execute(sa.select(Page.url))).scalars())
        assert "https://clearnet.example/x" not in urls  # clearnet child skipped
        ioc_types = set((await s.execute(sa.select(Ioc.ioc_type))).scalars())
        assert "btc" in ioc_types
        n_emb = (await s.execute(sa.select(sa.func.count()).select_from(Embedding))).scalar()
        assert n_emb == 4                 # one embedding per crawled page

    # Semantic search finds a relevant page.
    hits = await search(db, build_embedder(settings), "vendor market bitcoin", top_k=3)
    assert hits and hits[0]["url"].endswith("/a")

    # Resume: nothing is due for recrawl, so a second run crawls nothing new.
    _, db2, crawler2 = _make(tmp_path)
    stats2 = await crawler2.run([SEED])
    assert stats2["crawled"] == 0

    await db.dispose()
    await db2.dispose()


SEED2 = "http://seed2.onion/"
GRAPH2 = {
    SEED2: """<html><body>
        <a href="/bad">bad</a>
        <a href="/gone">gone</a>
    </body></html>""",
    "http://seed2.onion/bad": "<html><body>this page mentions a forbidden_marker here</body></html>",
    # /gone is intentionally absent -> the fetcher returns 404 -> dead
}


async def test_crawler_blocks_and_dead(tmp_path):
    settings = Settings()
    settings.max_workers = 2
    settings.embeddings_enabled = False
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'cd.db'}")
    await db.create_all()

    policy = CompliancePolicy(blocklist=[("test-cat", re.compile(r"forbidden_marker"))])
    crawler = Crawler(
        settings, db,
        fetcher=FakeFetcher(GRAPH2),
        scorer=KeywordScorer([]),
        policy=policy,
        enrichers=[],
    )
    stats = await crawler.run([SEED2])

    assert stats["blocked"] == 1
    assert stats["dead"] == 1

    async with db.session() as s:
        blocked = (
            await s.execute(sa.select(Page).where(Page.status == STATUS_BLOCKED))
        ).scalar_one()
        assert blocked.url.endswith("/bad")
        assert blocked.content is None            # body withheld
        assert blocked.content_sha256 is not None  # but hash kept for audit
        assert "test-cat" in (blocked.block_reason or "")

        dead = (await s.execute(sa.select(Page).where(Page.status == STATUS_DEAD))).scalar_one()
        assert dead.url.endswith("/gone")

    await db.dispose()


async def test_processing_error_is_a_failed_attempt_not_a_stuck_claim(tmp_path, monkeypatch):
    """A page whose processing raises used to stay in_progress with zero attempts,
    get reclaimed after the stale timeout, raise again, and loop forever. It must
    retry with backoff without inventing a host outage."""
    import umbra.crawl.crawler as crawler_module

    settings, db, crawler = _make(tmp_path)
    settings.max_workers = 1
    await db.create_all()

    real_parse = crawler_module.parse_page

    def exploding_parse(text, url):
        if url.endswith("/a"):
            raise ValueError("'dot' does not appear to be an IPv4 or IPv6 address")
        return real_parse(text, url)

    monkeypatch.setattr(crawler_module, "parse_page", exploding_parse)
    stats = await crawler.run([SEED])

    async with db.session() as s:
        row = (await s.execute(sa.select(Page).where(Page.url == "http://seed.onion/a"))).scalar_one()
        others = (await s.execute(
            sa.select(sa.func.count()).select_from(Page).where(Page.status == "crawled")
        )).scalar()
    assert row.status != "in_progress"
    assert row.attempts == 1 and row.processing_failures == 1
    assert row.consecutive_failures == 0
    assert "ValueError" in (row.error or "")
    assert row.next_crawl_at is not None      # retried with backoff, not immediately
    assert stats["processing_errors"] == 1 and stats["dead"] == 0
    assert others == 3                        # the rest of the crawl was unaffected
    await db.dispose()
