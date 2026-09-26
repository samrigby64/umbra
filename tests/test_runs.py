"""Tests for collection health.

This exists because of a real failure: a budget bug left the worker fetching
nothing for an entire cycle while logging the previous pass's totals, so the logs
read as healthy and the dashboards stayed green. The tests below are mostly about
the one distinction that makes the alarm trustworthy — a pass that crawls nothing
because there is nothing to do is fine; one that crawls nothing while work is
waiting is broken.
"""

import pytest
import datetime as dt
import sqlalchemy as sa

from umbra.db import Database
from umbra.models import STATUS_CRAWLED, STATUS_DISCOVERED, Event, Page, Run, utcnow
from umbra.runs import health, list_runs, purge_old_runs, reap_abandoned_runs, record_run


async def _db(tmp_path, name="runs.db"):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / name}")
    await db.create_all()
    return db


async def _queue(db, n: int) -> None:
    """Put ``n`` never-fetched links in the frontier — i.e. work is waiting."""
    async with db.session() as s:
        s.add_all([
            Page(url=f"http://x.onion/{i}", hostname="x.onion", status=STATUS_DISCOVERED,
                 depth=1, score=1.0, blocked=False, stored_content=False)
            for i in range(n)
        ])
        await s.commit()


async def test_records_a_pass_with_its_outcome(tmp_path):
    db = await _db(tmp_path)
    await _queue(db, 5)
    async with record_run(db, trigger="worker") as run:
        run.pages_crawled = 12
        run.pages_dead = 3
        run.iocs_found = 40
        run.new_alerts = 2
        run.actors = 7

    rows = await list_runs(db)
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "ok" and row["trigger"] == "worker"
    assert row["pages_crawled"] == 12 and row["iocs_found"] == 40
    assert row["work_waiting"] == 5      # snapshot taken before the pass ran
    assert row["stalled"] is False
    assert row["duration_s"] is not None
    await db.dispose()


async def test_crash_still_closes_the_run(tmp_path):
    """An interrupted pass that left no row would be indistinguishable from one
    that never started — the exact blind spot this is meant to remove."""
    db = await _db(tmp_path)
    with pytest.raises(RuntimeError):
        async with record_run(db) as run:
            run.pages_crawled = 3
            raise RuntimeError("tor died")

    row = (await list_runs(db))[0]
    assert row["status"] == "error"
    assert "tor died" in row["error"]
    assert row["finished_at"] is not None
    verdict = await health(db)
    assert verdict["status"] == "failing"
    await db.dispose()


async def test_idle_is_not_stalled(tmp_path):
    """Nothing crawled, nothing waiting: the frontier is drained, not broken.
    Crying wolf here is how an alarm gets ignored when it matters."""
    db = await _db(tmp_path)
    async with db.session() as s:  # one crawled page, nothing due, nothing queued
        s.add(Page(url="http://x.onion/", hostname="x.onion", status=STATUS_CRAWLED,
                   depth=0, score=1.0, content_sha256="s", blocked=False, stored_content=True))
        await s.commit()
    for _ in range(3):
        async with record_run(db):
            pass

    verdict = await health(db)
    assert verdict["status"] == "idle"
    assert verdict["consecutive_stalled"] == 0
    assert (await list_runs(db))[0]["stalled"] is False
    await db.dispose()


async def test_stalled_when_work_was_waiting(tmp_path):
    """The real bug: hundreds of links queued, zero pages fetched, no error."""
    db = await _db(tmp_path)
    await _queue(db, 395)
    async with record_run(db):
        pass
    assert (await health(db))["status"] == "ok"  # one quiet pass is not yet a fault

    async with record_run(db):
        pass
    verdict = await health(db)
    assert verdict["status"] == "stalled"
    assert verdict["consecutive_stalled"] == 2
    assert "395" in verdict["detail"]
    await db.dispose()


async def test_a_good_pass_clears_the_stall(tmp_path):
    db = await _db(tmp_path)
    await _queue(db, 10)
    for _ in range(3):
        async with record_run(db):
            pass
    assert (await health(db))["status"] == "stalled"

    async with record_run(db) as run:
        run.pages_crawled = 4
    verdict = await health(db)
    assert verdict["status"] == "ok"
    assert verdict["consecutive_stalled"] == 0
    await db.dispose()


async def test_health_before_anything_has_run(tmp_path):
    db = await _db(tmp_path)
    verdict = await health(db)
    assert verdict["status"] == "unknown" and verdict["last_run"] is None
    assert "Run the worker" in verdict["detail"]
    await db.dispose()


async def test_first_pass_in_progress_is_not_reported_as_never_started(tmp_path):
    """Telling someone to start the worker while the same response says one is
    running is the kind of contradiction that makes people stop reading status."""
    db = await _db(tmp_path)
    async with record_run(db):
        verdict = await health(db)
    assert verdict["status"] == "unknown"
    assert verdict["in_progress"] == 1
    assert "in progress" in verdict["detail"]
    assert "Run the worker" not in verdict["detail"]
    await db.dispose()


async def test_counts_events_emitted_during_the_pass(tmp_path):
    """Ties collection health to intelligence output: a pass can fetch pages and
    still be producing nothing new, which is worth being able to see."""
    db = await _db(tmp_path)
    async with db.session() as s:  # a pre-existing event must not be counted
        s.add(Event(kind="page_new", page_url="http://old.onion/", summary="old"))
        await s.commit()
        await s.execute(
            sa.update(Event).values(occurred_at=sa.text("'2020-01-01 00:00:00'"))
        )
        await s.commit()

    async with record_run(db) as run:
        run.pages_crawled = 1
        async with db.session() as s:
            s.add(Event(kind="page_new", page_url="http://new.onion/", summary="new"))
            await s.commit()

    assert (await list_runs(db))[0]["events_emitted"] == 1
    await db.dispose()


async def test_reaps_runs_abandoned_by_a_killed_process(tmp_path):
    """record_run closes its row on exception but not on SIGKILL, and killing a
    worker is routine. Left open, those rows inflate in-progress forever."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add(Run(status="running", trigger="worker", queued_at_start=100,
                  started_at=utcnow()-dt.timedelta(hours=1)))
        await s.commit()
    assert (await health(db))["in_progress"] == 1

    assert await reap_abandoned_runs(db) == 1
    assert (await health(db))["in_progress"] == 0
    row = (await list_runs(db))[0]
    assert row["status"] == "abandoned" and "abandoned" in row["error"]
    assert row["finished_at"] is not None

    assert await reap_abandoned_runs(db) == 0  # nothing left to reap
    await db.dispose()


async def test_restarting_the_worker_is_not_reported_as_a_failure(tmp_path):
    """Restarts are routine. If each one flipped health to 'failing' until the
    next pass finished, the indicator would be red during normal operations and
    nobody would trust it when something was genuinely wrong."""
    db = await _db(tmp_path)
    await _queue(db, 5)
    async with record_run(db) as run:  # a healthy pass, some time ago
        run.pages_crawled = 30
    async with db.session() as s:      # then a restart interrupts the next one
        s.add(Run(status="running", trigger="worker", queued_at_start=5,
                  started_at=utcnow()-dt.timedelta(hours=1)))
        await s.commit()
    await reap_abandoned_runs(db)

    verdict = await health(db)
    assert verdict["status"] == "ok"           # not "failing"
    assert verdict["last_run"]["pages_crawled"] == 30
    await db.dispose()


async def test_only_ever_interrupted_is_a_failure(tmp_path):
    """A worker that is always killed before finishing collects nothing, and
    excluding abandoned runs must not hide that."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add_all([Run(status="running", trigger="worker",
                      started_at=utcnow()-dt.timedelta(hours=1)) for _ in range(3)])
        await s.commit()
    await reap_abandoned_runs(db)

    verdict = await health(db)
    assert verdict["status"] == "failing"
    assert "interrupted" in verdict["detail"]
    await db.dispose()


async def test_reaping_leaves_a_live_run_alone_until_it_ends(tmp_path):
    db = await _db(tmp_path)
    async with record_run(db) as run:
        run.pages_crawled = 5
    assert await reap_abandoned_runs(db) == 0
    assert (await list_runs(db))[0]["status"] == "ok"
    await db.dispose()


async def test_purge_old_runs_keeps_recent(tmp_path):
    db = await _db(tmp_path)
    async with record_run(db) as run:
        run.pages_crawled = 1
    async with db.session() as s:
        s.add(Run(status="ok", trigger="worker", pages_crawled=1))
        await s.commit()
        await s.execute(
            sa.update(Run).where(Run.id == 2).values(started_at=sa.text("'2020-01-01 00:00:00'"))
        )
        await s.commit()

    assert await purge_old_runs(db, keep_days=30) == 1
    assert len(await list_runs(db)) == 1
    await db.dispose()


async def test_dead_worker_is_reported_stale_not_ok(tmp_path):
    """The walkthrough found a worker dead for 26 hours under a green banner:
    the verdict came from the last *completed* pass, which stays ok forever."""
    db = await _db(tmp_path)
    await _queue(db, 5)
    async with record_run(db) as run:
        run.pages_crawled = 40
    assert (await health(db, stale_after_s=3600))["status"] == "ok"

    async with db.session() as s:  # age the pass past the threshold
        await s.execute(sa.update(Run).values(
            started_at=sa.text("'2020-01-01 00:00:00'"),
            finished_at=sa.text("'2020-01-01 00:10:00'"),
        ))
        await s.commit()
    verdict = await health(db, stale_after_s=3600)
    assert verdict["status"] == "stale"
    assert "worker is not running" in verdict["detail"]
    assert "day(s)" in verdict["detail"]        # humanised, not "3,000,000 minutes"

    # ...but a fresh pass in flight means someone is collecting: not stale
    async with record_run(db):
        assert (await health(db, stale_after_s=3600))["status"] == "ok"
    await db.dispose()


async def test_a_pass_stuck_running_for_too_long_is_stale(tmp_path):
    """A 'running' row from a process that was killed without cleanup must not
    read as healthy activity forever."""
    db = await _db(tmp_path)
    async with record_run(db) as run:
        run.pages_crawled = 10
    async with db.session() as s:
        s.add(Run(status="running", trigger="worker", queued_at_start=1))
        await s.commit()
        await s.execute(sa.update(Run).where(Run.status == "running")
                        .values(started_at=sa.text("'2020-01-01 00:00:00'")))
        await s.commit()
    verdict = await health(db, stale_after_s=3600)
    assert verdict["status"] == "stale"
    assert "killed" in verdict["detail"]
    await db.dispose()


def test_humanized_durations_pick_a_sensible_unit():
    from umbra.runs import _humanize
    assert _humanize(45) == "45 second(s)"
    assert _humanize(600) == "10 minute(s)"
    assert _humanize(1570 * 60) == "26.2 hour(s)"
    assert _humanize(3 * 86_400) == "3.0 day(s)"
