"""Scheduler unit tests: adaptive recrawl scheduling and stale reclaim."""

import datetime as dt

import sqlalchemy as sa

from umbra.config import Settings
from umbra.crawl.scheduler import Scheduler
from umbra.db import Database
from umbra.models import STATUS_CRAWLED, STATUS_DEAD, STATUS_IN_PROGRESS, Ioc, Page, utcnow

URL = "http://x.onion/"


def _crawled(sha: str, content: str = "body text") -> Page:
    return Page(
        url=URL, status=STATUS_CRAWLED, content_sha256=sha, content=content,
        hostname="x", depth=0, score=1.0, blocked=False, stored_content=True,
    )


def _dead() -> Page:
    return Page(
        url=URL, status=STATUS_DEAD, error="boom",
        hostname="x", depth=0, score=1.0, blocked=False, stored_content=False,
    )


async def _row(db: Database) -> Page:
    async with db.session() as s:
        return (await s.execute(sa.select(Page).where(Page.url == URL))).scalar_one()


async def _ioc_values(db: Database) -> set[str]:
    async with db.session() as s:
        return set((await s.execute(sa.select(Ioc.value).where(Ioc.page_url == URL))).scalars())


async def _force_due(db: Database) -> None:
    async with db.session() as s:
        row = (await s.execute(sa.select(Page).where(Page.url == URL))).scalar_one()
        row.next_crawl_at = utcnow() - dt.timedelta(seconds=1)
        await s.commit()


async def _interval(db: Database) -> int:
    async with db.session() as s:
        row = (await s.execute(sa.select(Page).where(Page.url == URL))).scalar_one()
        return row.recrawl_interval_s


async def test_recrawl_interval_adapts(tmp_path):
    settings = Settings()
    settings.recrawl_interval_s = 100
    settings.recrawl_interval_max_s = 1000
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 's.db'}")
    await db.create_all()
    sched = Scheduler(db, settings)
    await sched.load()
    await sched.seed([URL])

    # First crawl: content is new => changed, interval = base.
    assert await sched.claim() is not None
    assert await sched.complete(_crawled("A"), []) is True
    assert await _interval(db) == 100

    # Recrawl, content unchanged => interval doubles.
    await _force_due(db)
    assert await sched.claim() is not None
    assert await sched.complete(_crawled("A"), []) is False
    assert await _interval(db) == 200

    # Recrawl, content changed => interval resets to base.
    await _force_due(db)
    assert await sched.claim() is not None
    assert await sched.complete(_crawled("B"), []) is True
    assert await _interval(db) == 100

    await db.dispose()


async def test_stale_in_progress_is_reclaimed(tmp_path):
    settings = Settings()
    settings.reclaim_after_s = 60
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'r.db'}")
    await db.create_all()
    sched = Scheduler(db, settings)
    await sched.load()
    await sched.seed([URL])

    # Simulate a worker that claimed the page then died (never completed).
    assert await sched.claim() is not None
    assert await sched.claim() is None  # nothing else claimable right now

    async with db.session() as s:
        row = (await s.execute(sa.select(Page).where(Page.url == URL))).scalar_one()
        assert row.status == STATUS_IN_PROGRESS
        row.claimed_at = utcnow() - dt.timedelta(seconds=120)  # older than reclaim window
        await s.commit()

    # The stale claim is now reclaimable.
    assert await sched.claim() is not None
    await db.dispose()


async def test_fetch_failure_preserves_content_then_dies(tmp_path):
    settings = Settings()
    settings.recrawl_interval_s = 100
    settings.max_fetch_failures = 3
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'f.db'}")
    await db.create_all()
    sched = Scheduler(db, settings)
    await sched.load()
    await sched.seed([URL])

    # Successful first crawl stores content.
    item = await sched.claim()
    await sched.complete(_crawled("SHA1"), [], claim_token=item.claim_token)

    # First transient failure: content preserved, page still schedulable.
    await _force_due(db)
    item = await sched.claim()
    await sched.complete(_dead(), [], claim_token=item.claim_token)
    row = await _row(db)
    assert row.content == "body text"        # NOT erased by the failed fetch
    assert row.content_sha256 == "SHA1"
    assert row.consecutive_failures == 1
    assert row.status == STATUS_CRAWLED       # still claimable when due
    assert row.next_crawl_at is not None

    # Two more failures reach the cap -> permanently dead, content STILL preserved.
    for _ in range(2):
        await _force_due(db)
        item = await sched.claim()
        await sched.complete(_dead(), [], claim_token=item.claim_token)
    row = await _row(db)
    assert row.status == STATUS_DEAD
    assert row.next_crawl_at is None
    assert row.content == "body text"
    await db.dispose()


async def test_iocs_are_replaced_not_accumulated(tmp_path):
    settings = Settings()
    settings.recrawl_interval_s = 100
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'i.db'}")
    await db.create_all()
    sched = Scheduler(db, settings)
    await sched.load()
    await sched.seed([URL])

    item = await sched.claim()
    await sched.complete(_crawled("SHA1"), [Ioc(page_url=URL, ioc_type="btc", value="A")],
                         claim_token=item.claim_token)
    assert await _ioc_values(db) == {"A"}

    # Changed content -> IOC set replaced, not unioned.
    await _force_due(db)
    item = await sched.claim()
    await sched.complete(_crawled("SHA2"), [Ioc(page_url=URL, ioc_type="btc", value="B")],
                         claim_token=item.claim_token)
    assert await _ioc_values(db) == {"B"}

    # Unchanged recrawl (no new iocs passed) -> existing IOCs kept.
    await _force_due(db)
    item = await sched.claim()
    await sched.complete(_crawled("SHA2"), [], claim_token=item.claim_token)
    assert await _ioc_values(db) == {"B"}
    await db.dispose()


async def test_force_seed_retries_a_failed_url(tmp_path):
    """An explicit 'crawl this now' must override the failure backoff — otherwise
    fixing a misconfiguration and re-submitting the same URL does nothing."""
    settings = Settings()
    settings.recrawl_interval_s = 86_400  # a failed fetch backs off a whole day
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'force.db'}")
    await db.create_all()
    sched = Scheduler(db, settings)
    await sched.load()
    await sched.seed([URL])

    # First attempt fails (e.g. Tor wasn't running) -> dead, due in ~1 day.
    item = await sched.claim()
    await sched.complete(_dead(), [], claim_token=item.claim_token)
    assert (await _row(db)).status == STATUS_DEAD
    assert await sched.claim() is None  # backed off: nothing claimable

    # Re-seeding without force is a no-op (URL already known, still backed off).
    assert await sched.seed([URL]) == 0
    assert await sched.claim() is None

    # Re-seeding WITH force makes it crawlable again right now.
    assert await sched.seed([URL], force=True) == 1
    assert await sched.claim() is not None
    await db.dispose()


async def test_stale_completion_is_discarded(tmp_path):
    settings = Settings()
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'd.db'}")
    await db.create_all()
    sched = Scheduler(db, settings)
    await sched.load()
    await sched.seed([URL])

    item = await sched.claim()  # this worker's claim token
    # Simulate another worker reclaiming the row (bumps claim_seq).
    async with db.session() as s:
        row = (await s.execute(sa.select(Page).where(Page.url == URL))).scalar_one()
        row.claim_seq = row.claim_seq + 1
        await s.commit()

    # The original worker's completion must be discarded (no write-through).
    changed = await sched.complete(_crawled("SHA1"), [], claim_token=item.claim_token)
    assert changed is None
    row = await _row(db)
    assert row.content_sha256 is None       # nothing was written
    assert row.status == STATUS_IN_PROGRESS
    await db.dispose()
