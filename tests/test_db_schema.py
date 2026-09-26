"""Tests for in-place schema upgrades.

``create_all`` only creates missing *tables*. Shipping a new column to a customer
who already has the table does nothing, and the failure surfaces as a runtime
error on the first query that touches it — long after deploy, and nowhere near
the cause.
"""

import sqlalchemy as sa

from umbra.db import Database
from umbra.models import Alert, Watchlist


async def _columns(db, table: str) -> set[str]:
    async with db.session() as s:
        rows = (await s.execute(sa.text(f"PRAGMA table_info({table})"))).all()
    return {r[1] for r in rows}


async def _indexes(db, table: str) -> set[str]:
    async with db.session() as s:
        rows = (await s.execute(sa.text(f"PRAGMA index_list({table})"))).all()
    return {r[1] for r in rows}


async def test_adds_missing_columns_and_swaps_the_obsolete_index(tmp_path):
    """Simulates an existing deployment: build the old alerts table by hand, then
    let the upgrade bring it forward."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'old.db'}"
    db = Database(url)
    async with db.session() as s:
        await s.execute(sa.text("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watchlist_id INTEGER,
                page_url VARCHAR(2048),
                matched_value VARCHAR(512),
                delivered BOOLEAN,
                created_at DATETIME
            )"""))
        await s.execute(
            sa.text("CREATE UNIQUE INDEX ix_alert_watch_page ON alerts (watchlist_id, page_url)")
        )
        await s.execute(sa.text(
            "INSERT INTO alerts (watchlist_id, page_url, matched_value, delivered) "
            "VALUES (1, 'http://x.onion/', 'acme', 0)"
        ))
        await s.commit()

    assert "dedup_key" not in await _columns(db, "alerts")
    applied = await db.upgrade_schema()

    assert "alerts.dedup_key" in applied and "alerts.event_id" in applied
    assert "-ix_alert_watch_page" in applied
    cols = await _columns(db, "alerts")
    assert {"dedup_key", "event_id"} <= cols
    indexes = await _indexes(db, "alerts")
    assert "ix_alert_watch_page" not in indexes
    assert "ix_alert_watch_dedup" in indexes

    # the pre-existing row survives — an upgrade must not discard alert history
    async with db.session() as s:
        rows = (await s.execute(sa.select(Alert))).scalars().all()
    assert len(rows) == 1 and rows[0].matched_value == "acme"

    # ...and it is backfilled. A NULL dedup_key reads as "never deduplicated",
    # so without this the next evaluation re-alerts the entire alert history.
    assert rows[0].dedup_key == "http://x.onion/"
    assert any(a.startswith("~alerts.dedup_key") for a in applied)
    await db.dispose()


async def test_migrated_alerts_do_not_fire_again(tmp_path):
    """End-to-end version of the above: a customer upgrading in place must not be
    re-notified about every match they have already seen."""
    from umbra.alerting import evaluate_watchlists
    from umbra.models import STATUS_CRAWLED, Page

    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'migrated.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add(Page(url="http://x.onion/", hostname="x.onion", status=STATUS_CRAWLED,
                   depth=0, score=1.0, content="acme corp dump",
                   blocked=False, stored_content=True))
        s.add(Watchlist(name="w", kind="keyword", value="acme corp"))
        await s.commit()
    assert (await evaluate_watchlists(db))["new_alerts"] == 1

    # simulate a row written by the old build, which had no dedup_key
    async with db.session() as s:
        await s.execute(sa.text("UPDATE alerts SET dedup_key = NULL"))
        await s.commit()
    await db.upgrade_schema()

    assert (await evaluate_watchlists(db))["new_alerts"] == 0
    await db.dispose()


async def test_upgrade_is_idempotent(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'fresh.db'}")
    await db.create_all()          # create_all already calls upgrade_schema
    assert await db.upgrade_schema() == []
    await db.dispose()


async def test_new_column_is_usable_after_upgrade(tmp_path):
    """The point of the exercise: the ORM can write the column it just added."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'usable.db'}"
    db = Database(url)
    await db.create_all()
    async with db.session() as s:
        s.add(Watchlist(name="w", kind="event", value="notable"))
        await s.commit()
        s.add(Alert(watchlist_id=1, page_url="u", matched_value="m",
                    dedup_key="event:7", event_id=7))
        await s.commit()
        got = (await s.execute(sa.select(Alert))).scalars().one()
    assert got.dedup_key == "event:7" and got.event_id == 7
    await db.dispose()
