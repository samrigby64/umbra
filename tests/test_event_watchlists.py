"""Tests for event-driven watchlists — alerting on change, not just presence.

The distinction under test throughout: a content watchlist asks "is this in the
corpus?" and should fire once; an event watchlist asks "did something happen?"
and must fire again each time it happens. Collapsing the two is what would make
a customer miss the second outage.
"""

import sqlalchemy as sa

from umbra.alerting import evaluate_watchlists, parse_event_value
from umbra.db import Database
from umbra.models import STATUS_CRAWLED, Alert, Event, Ioc, Page, Watchlist
from umbra import timeline


async def _db(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'alerts.db'}")
    await db.create_all()
    return db


async def _add_event(db, kind, host="market.onion", url="http://market.onion/", summary="x"):
    async with db.session() as s:
        event = Event(kind=kind, hostname=host, page_url=url, summary=summary)
        s.add(event)
        await s.commit()
        return event.id


async def _watch(db, kind, value, **kw):
    async with db.session() as s:
        wl = Watchlist(name=f"{kind}:{value}", kind=kind, value=value, **kw)
        s.add(wl)
        await s.commit()
        return wl.id


async def _alerts(db):
    async with db.session() as s:
        return (await s.execute(sa.select(Alert).order_by(Alert.id))).scalars().all()


def test_parse_event_value():
    assert parse_event_value("page_unreachable") == ("page_unreachable", None)
    assert parse_event_value("page_unreachable@x.onion") == ("page_unreachable", "x.onion")
    assert parse_event_value("notable") == ("notable", None)


async def test_event_watchlist_alerts_on_an_outage(tmp_path):
    db = await _db(tmp_path)
    await _watch(db, "event", "page_unreachable")
    await _add_event(db, timeline.PAGE_UNREACHABLE, summary="Stopped responding: Example Market")

    result = await evaluate_watchlists(db)
    assert result["new_alerts"] == 1
    alert = (await _alerts(db))[0]
    assert alert.event_id is not None
    assert "Example Market" in alert.matched_value
    await db.dispose()


async def test_repeat_outages_each_alert(tmp_path):
    """The whole point: down, back, down again is three things worth knowing.
    Keyed on the page instead of the event, only the first would ever fire."""
    db = await _db(tmp_path)
    await _watch(db, "event", "notable")

    await _add_event(db, timeline.PAGE_UNREACHABLE, summary="down")
    assert (await evaluate_watchlists(db))["new_alerts"] == 1
    assert (await evaluate_watchlists(db))["new_alerts"] == 0  # nothing new happened

    await _add_event(db, timeline.PAGE_RECOVERED, summary="back")
    await _add_event(db, timeline.PAGE_UNREACHABLE, summary="down again")
    assert (await evaluate_watchlists(db))["new_alerts"] == 2

    assert len(await _alerts(db)) == 3
    await db.dispose()


async def test_notable_excludes_routine_churn(tmp_path):
    db = await _db(tmp_path)
    await _watch(db, "event", "notable")
    await _add_event(db, timeline.PAGE_CHANGED, summary="content moved")
    await _add_event(db, timeline.PAGE_NEW, summary="new page")
    await _add_event(db, timeline.INDICATOR_NEW, summary="new pgp key")

    assert (await evaluate_watchlists(db))["new_alerts"] == 1
    assert "pgp" in (await _alerts(db))[0].matched_value
    await db.dispose()


async def test_host_scoping(tmp_path):
    """A customer watching one marketplace does not want every outage on the
    dark web."""
    db = await _db(tmp_path)
    await _watch(db, "event", "page_unreachable@mine.onion")
    await _add_event(db, timeline.PAGE_UNREACHABLE, host="theirs.onion", summary="not mine")
    await _add_event(db, timeline.PAGE_UNREACHABLE, host="mine.onion", summary="mine")

    assert (await evaluate_watchlists(db))["new_alerts"] == 1
    assert (await _alerts(db))[0].matched_value == "mine"
    await db.dispose()


async def test_content_watchlist_still_fires_once_per_page(tmp_path):
    """Regression: the dedup change must not make content watchlists repeat."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add(Page(url="http://x.onion/", hostname="x.onion", status=STATUS_CRAWLED,
                   depth=0, score=1.0, content="acme corp breach dump",
                   blocked=False, stored_content=True))
        s.add(Ioc(page_url="http://x.onion/", ioc_type="btc", value="ADDR1"))
        await s.commit()
    await _watch(db, "keyword", "acme corp")
    await _watch(db, "ioc", "ADDR1")

    assert (await evaluate_watchlists(db))["new_alerts"] == 2
    assert (await evaluate_watchlists(db))["new_alerts"] == 0  # same facts, no repeat
    await db.dispose()


async def test_two_watchlists_on_the_same_event_both_alert(tmp_path):
    """Dedup is per watchlist — two customers watching the same market must both
    be told, which a global dedup key would prevent."""
    db = await _db(tmp_path)
    await _watch(db, "event", "notable")
    await _watch(db, "event", "page_unreachable")
    await _add_event(db, timeline.PAGE_UNREACHABLE, summary="down")

    assert (await evaluate_watchlists(db))["new_alerts"] == 2
    await db.dispose()


async def test_webhook_payload_carries_the_event(tmp_path, monkeypatch):
    """An alert saying only 'something changed' costs the customer a round trip
    before they can act on it."""
    db = await _db(tmp_path)
    await _watch(db, "event", "notable", webhook_url="https://hooks.example/x")
    await _add_event(
        db, timeline.INDICATOR_NEW, summary="New pgp_fp on Vendor X", url="http://v.onion/"
    )

    sent: list[dict] = []

    class FakeResponse:
        status_code = 200

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            sent.append(json)
            return FakeResponse()

    monkeypatch.setattr("umbra.alerting.httpx.AsyncClient", FakeClient)
    result = await evaluate_watchlists(db)

    assert result["delivered"] == 1
    assert sent[0]["event"]["kind"] == timeline.INDICATOR_NEW
    assert sent[0]["event"]["host"] == "market.onion"
    assert "Vendor X" in sent[0]["event"]["summary"]
    await db.dispose()


async def test_history_is_bounded_when_a_watchlist_is_added_late(tmp_path):
    """Adding a watchlist to a corpus with months of history must not fire
    thousands of alerts about things that happened before anyone was watching."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add_all([
            Event(kind=timeline.PAGE_UNREACHABLE, hostname="x.onion",
                  page_url=f"http://x.onion/{i}", summary=f"down {i}")
            for i in range(600)
        ])
        await s.commit()
    await _watch(db, "event", "page_unreachable")

    result = await evaluate_watchlists(db)
    assert result["new_alerts"] == 500  # capped, newest first
    await db.dispose()
