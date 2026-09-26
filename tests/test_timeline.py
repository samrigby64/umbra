"""Tests for the change/liveness timeline.

The timeline is the only record of history — every other table is overwritten by
the next recrawl — so these walk a page through a full lifecycle (appear, change,
go dark, come back) and assert the log matches what actually happened.
"""

import datetime as dt

import sqlalchemy as sa

from umbra import timeline
from umbra.config import Settings
from umbra.crawl.scheduler import Scheduler
from umbra.db import Database
from umbra.models import STATUS_CRAWLED, STATUS_DEAD, Event, Ioc, Page


async def _scheduler(tmp_path, **overrides):
    settings = Settings()
    settings.database_url = f"sqlite+aiosqlite:///{tmp_path / 'tl.db'}"
    settings.recrawl_interval_s = 60
    settings.max_fetch_failures = 3
    for key, value in overrides.items():
        setattr(settings, key, value)
    db = Database(settings.database_url)
    await db.create_all()
    scheduler = Scheduler(db, settings)
    await scheduler.load()
    return scheduler, db


def _page(url: str, sha: str | None, status: str = STATUS_CRAWLED, host: str = "x.onion", **kw) -> Page:
    # depth/score are set explicitly: complete() copies them onto the stored row,
    # and column defaults don't apply to a transient object.
    return Page(
        url=url, hostname=host, status=status, content_sha256=sha, depth=0, score=1.0,
        fetched_at=dt.datetime.now(dt.timezone.utc), blocked=False,
        stored_content=sha is not None, **kw
    )


async def _kinds(db) -> list[str]:
    async with db.session() as s:
        rows = (await s.execute(sa.select(Event.kind).order_by(Event.id))).scalars().all()
    return list(rows)


async def _claim(scheduler, url):
    """Claim ``url`` as the crawler would once its recrawl time arrives.

    Rewinds ``next_crawl_at`` rather than force-seeding: a forced seed also clears
    ``consecutive_failures``, which would model an operator hitting Crawl rather
    than the passage of time, and silently reset the backoff under the test.
    """
    await scheduler.seed([url])
    async with scheduler.db.session() as session:
        row = (
            await session.execute(sa.select(Page).where(Page.url == url))
        ).scalar_one_or_none()
        if row is not None:
            row.next_crawl_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
            if row.status == STATUS_DEAD and row.content_sha256 is None:
                row.status = "discovered"  # never-fetched page: still eligible
            await session.commit()
    item = await scheduler.claim()
    assert item is not None and item.url == url
    return item


async def test_page_lifecycle_is_recorded(tmp_path):
    scheduler, db = await _scheduler(tmp_path)
    url = "http://x.onion/"

    # 1. first successful fetch -> new page
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-a", title="Market"), [], claim_token=item.claim_token)
    assert await _kinds(db) == [timeline.PAGE_NEW]

    # 2. refetched, identical -> silence (steady state is not news)
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-a"), [], claim_token=item.claim_token)
    assert await _kinds(db) == [timeline.PAGE_NEW]

    # 3. content differs -> change recorded
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-b"), [], claim_token=item.claim_token)
    assert await _kinds(db) == [timeline.PAGE_NEW, timeline.PAGE_CHANGED]

    # 4. service stops answering -> outage recorded once, not per retry
    for _ in range(2):
        item = await _claim(scheduler, url)
        await scheduler.complete(
            _page(url, None, status=STATUS_DEAD, error="timeout"), [], claim_token=item.claim_token
        )
    assert await _kinds(db) == [
        timeline.PAGE_NEW, timeline.PAGE_CHANGED, timeline.PAGE_UNREACHABLE,
    ]

    # 5. and comes back
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-c"), [], claim_token=item.claim_token)
    assert await _kinds(db) == [
        timeline.PAGE_NEW, timeline.PAGE_CHANGED, timeline.PAGE_UNREACHABLE,
        timeline.PAGE_RECOVERED, timeline.PAGE_CHANGED,
    ]
    await db.dispose()


async def test_giving_up_records_a_death(tmp_path):
    scheduler, db = await _scheduler(tmp_path, max_fetch_failures=2)
    url = "http://gone.onion/"
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-a"), [], claim_token=item.claim_token)
    for _ in range(2):
        item = await _claim(scheduler, url)
        await scheduler.complete(
            _page(url, None, status=STATUS_DEAD, error="conn refused"), [],
            claim_token=item.claim_token,
        )
    kinds = await _kinds(db)
    assert kinds.count(timeline.PAGE_DEAD) == 1
    assert timeline.PAGE_UNREACHABLE in kinds
    await db.dispose()


async def test_new_actor_identifier_is_flagged(tmp_path):
    """The vendor-rotation signal: a key that wasn't on the page before."""
    scheduler, db = await _scheduler(tmp_path)
    url = "http://vendor.onion/"
    old_key = "A" * 40
    new_key = "B" * 40

    item = await _claim(scheduler, url)
    await scheduler.complete(
        _page(url, "sha-a"),
        [Ioc(page_url=url, ioc_type="pgp_fp", value=old_key)],
        claim_token=item.claim_token,
    )
    item = await _claim(scheduler, url)
    await scheduler.complete(
        _page(url, "sha-b"),
        [
            Ioc(page_url=url, ioc_type="pgp_fp", value=old_key),  # unchanged: silent
            Ioc(page_url=url, ioc_type="pgp_fp", value=new_key),  # rotated: flagged
            Ioc(page_url=url, ioc_type="onion", value="noise.onion"),  # churny: ignored
        ],
        claim_token=item.claim_token,
    )

    events = await timeline.list_events(db, kind=timeline.INDICATOR_NEW)
    assert len(events) == 1
    assert events[0]["detail"] == new_key
    await db.dispose()


async def test_first_fetch_does_not_flag_every_identifier(tmp_path):
    """On a page's first fetch everything is new, which is not news."""
    scheduler, db = await _scheduler(tmp_path)
    url = "http://fresh.onion/"
    item = await _claim(scheduler, url)
    await scheduler.complete(
        _page(url, "sha-a"),
        [Ioc(page_url=url, ioc_type="btc", value="ADDR1")],
        claim_token=item.claim_token,
    )
    assert await timeline.list_events(db, kind=timeline.INDICATOR_NEW) == []
    await db.dispose()


async def test_notable_filter_drops_routine_churn(tmp_path):
    scheduler, db = await _scheduler(tmp_path)
    url = "http://x.onion/"
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-a"), [], claim_token=item.claim_token)
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-b"), [], claim_token=item.claim_token)
    item = await _claim(scheduler, url)
    await scheduler.complete(
        _page(url, None, status=STATUS_DEAD, error="timeout"), [], claim_token=item.claim_token
    )

    everything = await timeline.list_events(db)
    notable = await timeline.list_events(db, notable_only=True)
    assert len(everything) == 3
    assert [e["kind"] for e in notable] == [timeline.PAGE_UNREACHABLE]
    await db.dispose()


async def test_manual_retries_do_not_duplicate_one_outage(tmp_path):
    """Forcing a crawl clears consecutive_failures, so anything keyed off that
    counter logs a fresh outage on every click and misses the recovery after."""
    scheduler, db = await _scheduler(tmp_path)
    url = "http://x.onion/"

    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-a"), [], claim_token=item.claim_token)

    # operator hits Crawl three times while the service is down
    for _ in range(3):
        await scheduler.seed([url], force=True)
        item = await scheduler.claim()
        await scheduler.complete(
            _page(url, None, status=STATUS_DEAD, error="timeout"), [],
            claim_token=item.claim_token,
        )
    assert (await _kinds(db)).count(timeline.PAGE_UNREACHABLE) == 1

    # ...and it comes back on a forced crawl, with the counter already zeroed
    await scheduler.seed([url], force=True)
    item = await scheduler.claim()
    await scheduler.complete(_page(url, "sha-b"), [], claim_token=item.claim_token)
    assert (await _kinds(db)).count(timeline.PAGE_RECOVERED) == 1
    await db.dispose()


async def test_backfill_reconstructs_history_and_is_idempotent(tmp_path):
    """A corpus crawled before the timeline existed still holds real history."""
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'bf.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add_all([
            # was reachable, now isn't -> went dark
            Page(url="http://gone.onion/", hostname="gone.onion", status=STATUS_DEAD,
                 content_sha256="s", title="Market", depth=0, score=1.0, blocked=False,
                 stored_content=True, fetched_at=dt.datetime.now(dt.timezone.utc)),
            # never answered at all -> different fact entirely
            Page(url="http://never.onion/", hostname="never.onion", status=STATUS_DEAD,
                 content_sha256=None, depth=0, score=1.0, blocked=False, stored_content=False),
            Page(url="http://live.onion/", hostname="live.onion", status=STATUS_CRAWLED,
                 content_sha256="s2", depth=0, score=1.0, blocked=False, stored_content=True),
        ])
        await s.commit()

    first = await timeline.backfill(db)
    assert first["events"] > 0
    kinds = await _kinds(db)
    assert kinds.count(timeline.PAGE_UNREACHABLE) == 1  # gone.onion went dark
    assert kinds.count(timeline.PAGE_DEAD) == 1         # never.onion never answered
    assert kinds.count(timeline.PAGE_NEW) == 2          # the two with stored content

    # re-running must not duplicate anything
    assert (await timeline.backfill(db))["events"] == 0
    assert await _kinds(db) == kinds

    # reconstructed entries are labelled, never passed off as live detections
    events = await timeline.list_events(db)
    assert all(e["detail"] == "reconstructed from stored page state" for e in events)
    await db.dispose()


async def test_liveness_reports_down_hosts_first_with_offline_time(tmp_path):
    scheduler, db = await _scheduler(tmp_path, max_fetch_failures=1)
    good, bad = "http://up.onion/", "http://down.onion/"

    item = await _claim(scheduler, good)
    await scheduler.complete(
        _page(good, "s", host="up.onion"), [], claim_token=item.claim_token
    )
    item = await _claim(scheduler, bad)
    await scheduler.complete(
        _page(bad, "s", host="down.onion"), [], claim_token=item.claim_token
    )
    item = await _claim(scheduler, bad)
    await scheduler.complete(
        _page(bad, None, status=STATUS_DEAD, host="down.onion", error="timeout"),
        [], claim_token=item.claim_token,
    )

    hosts = await timeline.host_liveness(db)
    by_host = {h["host"]: h for h in hosts}
    assert hosts[0]["host"] == "down.onion"  # outages surface first
    assert by_host["down.onion"]["state"] == "down"
    assert by_host["down.onion"]["offline_since"] is not None
    assert by_host["up.onion"]["state"] == "up"
    assert by_host["up.onion"]["offline_since"] is None
    await db.dispose()


async def test_liveness_separates_went_dark_from_never_answered(tmp_path):
    """Both are 'dead' in the page table, but only one is an outage. A service
    that never answered on any attempt is noise; one that was up and stopped is
    the exit-scam / seizure signal, and it sorts first."""
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'never.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add_all([
            Page(url="http://dark.onion/", hostname="dark.onion", status=STATUS_DEAD,
                 content_sha256="had-content", depth=0, score=1.0, blocked=False,
                 stored_content=True),
            Page(url="http://never.onion/", hostname="never.onion", status=STATUS_DEAD,
                 content_sha256=None, depth=0, score=1.0, blocked=False, stored_content=False),
            Page(url="http://up.onion/", hostname="up.onion", status=STATUS_CRAWLED,
                 content_sha256="s", depth=0, score=1.0, blocked=False, stored_content=True),
        ])
        await s.commit()

    hosts = await timeline.host_liveness(db)
    states = {h["host"]: h["state"] for h in hosts}
    assert states == {"dark.onion": "down", "never.onion": "never", "up.onion": "up"}
    assert [h["host"] for h in hosts] == ["dark.onion", "up.onion", "never.onion"]
    await db.dispose()


async def test_a_service_that_goes_dark_shows_as_down_before_it_is_given_up_on(tmp_path):
    """Found by the synthetic demo lab: a shop went dark, the timeline recorded
    it, and Service status still said "up". A failed recrawl keeps the page
    "crawled" (its archived content must survive) and only raises its failure
    count, and liveness read the status alone — so no outage ever displayed."""
    scheduler, db = await _scheduler(tmp_path)  # max_fetch_failures=3: stays "crawled"
    url = "http://shop.onion/"
    item = await _claim(scheduler, url)
    await scheduler.complete(_page(url, "sha-a", host="shop.onion"), [],
                             claim_token=item.claim_token)
    assert {h["host"]: h["state"] for h in await timeline.host_liveness(db)} == {"shop.onion": "up"}

    item = await _claim(scheduler, url)
    await scheduler.complete(
        _page(url, None, status=STATUS_DEAD, host="shop.onion", error="timeout"), [],
        claim_token=item.claim_token,
    )
    async with db.session() as s:
        row = (await s.execute(sa.select(Page).where(Page.url == url))).scalar_one()
    assert row.status == STATUS_CRAWLED and row.consecutive_failures == 1  # the trap

    host = (await timeline.host_liveness(db))[0]
    assert host["state"] == "down"
    assert host["failing"] == 1 and host["live"] == 0
    assert host["offline_since"] is not None  # agrees with the timeline event
    await db.dispose()
