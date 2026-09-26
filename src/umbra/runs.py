"""Collection health: did the pipeline actually do anything?

Every other part of this system reports on the dark web. This part reports on
*us* — whether collection is still running, and whether it is accomplishing
anything when it does. Those are different questions from "is the API up", and
the second one is the one that bites: a crawler that fetches nothing throws no
exception, fails no health check, and leaves a database full of yesterday's
intelligence that still renders perfectly.

The core distinction is between **idle** and **stalled**. A pass that crawls
nothing because the frontier is drained and no page is due for recrawl is
working correctly. A pass that crawls nothing while hundreds of links sit queued
is broken. Both look identical in a log line reading ``crawled: 0``, so each run
snapshots how much work was available when it began, and the verdict is drawn
from that rather than from the count alone.
"""

from __future__ import annotations

import contextlib
import asyncio
import dataclasses
import datetime as dt

import sqlalchemy as sa

from .db import Database
from .logging import get_logger
from .models import STATUS_CRAWLED, STATUS_DISCOVERED, Event, Page, Run, utcnow
from .run_context import current_run

log = get_logger("runs")

# Two consecutive stalled passes, not one: a single pass can legitimately crawl
# nothing if every queued link belongs to a host that is currently failing and
# backing off. Two in a row with work waiting is a real fault.
STALL_THRESHOLD = 2


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    """Treat a stored timestamp as UTC if the driver dropped the timezone.

    SQLite has no native datetime type, so ``DateTime(timezone=True)`` columns
    round-trip as *naive* values even though they were written aware. Mixing the
    two raises at subtraction time. The same trap silently broke claim-token
    comparison elsewhere in this codebase, where it discarded every completion
    rather than raising — so normalise on read instead of trusting the driver.
    """
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value


@dataclasses.dataclass
class RunResult:
    """Filled in by the caller during the pass; persisted when it ends."""

    pages_crawled: int = 0
    pages_dead: int = 0
    iocs_found: int = 0
    new_alerts: int = 0
    actors: int = 0
    processing_errors: int = 0


async def _work_available(session, settings=None) -> tuple[int, int]:
    """(queued, due-for-recrawl) — how much there was to do at pass start."""
    if settings is not None:
        scope = [Page.depth <= settings.max_depth, Page.next_crawl_at <= utcnow()]
        if settings.allowed_hosts:
            scope.append(Page.hostname.in_(settings.allowed_hosts))
        queued = await session.scalar(sa.select(sa.func.count()).select_from(Page).where(
            *scope, Page.status == STATUS_DISCOVERED
        ))
        due = await session.scalar(sa.select(sa.func.count()).select_from(Page).where(
            *scope, Page.status.in_([STATUS_CRAWLED, "dead"])
        ))
        return int(queued), int(due)
    queued = (
        await session.execute(
            sa.select(sa.func.count()).select_from(Page).where(Page.status == STATUS_DISCOVERED)
        )
    ).scalar_one()
    due = (
        await session.execute(
            sa.select(sa.func.count())
            .select_from(Page)
            .where(Page.status == STATUS_CRAWLED, Page.next_crawl_at.isnot(None),
                   Page.next_crawl_at <= utcnow())
        )
    ).scalar_one()
    return int(queued), int(due)


async def reap_abandoned_runs(db: Database, stale_after_s: int = 300) -> int:
    """Close out ``running`` rows left behind by a process that was killed.

    ``record_run`` closes its row on exception, but not on SIGKILL — and a worker
    being force-killed is routine (restarts, container replacement, Ctrl-C in a
    terminal that doesn't forward the signal). Left alone those rows stay
    ``running`` forever and permanently inflate the in-progress count, so the
    health view slowly fills with passes that ended hours ago.

    Called at worker startup. Only expired heartbeats (or old legacy runs with
    no heartbeat) are reaped; another process may still own a healthy run.
    """
    async with db.session() as session:
        result = await session.execute(
            sa.update(Run)
            .where(Run.status == "running", sa.func.coalesce(
                Run.heartbeat_at, Run.started_at
            ) < utcnow() - dt.timedelta(seconds=stale_after_s))
            .values(
                # Its own status, not "error": restarting a worker is routine
                # (deploys, container replacement, Ctrl-C), and reporting each one
                # as a collection failure would fire the alarm on healthy
                # operations. An alarm that cries wolf during normal work is worse
                # than none, because people stop reading it.
                status="abandoned",
                finished_at=utcnow(),
                error="abandoned - the process ended before the pass finished",
            )
        )
        await session.commit()
    reaped = int(result.rowcount or 0)
    if reaped:
        log.warning("reaped %d abandoned run(s) from a previous process", reaped)
    return reaped


@contextlib.asynccontextmanager
async def record_run(db: Database, trigger: str = "worker", settings=None):
    """Record a collection pass. Yields a :class:`RunResult` for the caller to fill.

    A crash still closes the row, marked ``error`` — an interrupted pass that
    left no trace would be indistinguishable from one that never started, which
    is precisely the blind spot this exists to remove.
    """
    async with db.session() as session:
        queued, due = await _work_available(session, settings)
        run = Run(trigger=trigger, status="running", queued_at_start=queued, due_at_start=due,
                  heartbeat_at=utcnow())
        session.add(run)
        await session.commit()
        run_id = run.id

    result = RunResult()
    error: str | None = None

    async def pulse():
        while True:
            await asyncio.sleep(30)
            async with db.session() as s:
                await s.execute(sa.update(Run).where(Run.id == run_id).values(heartbeat_at=utcnow()))
                await s.commit()

    heartbeat = asyncio.create_task(pulse())
    token = current_run.set(run_id)
    try:
        yield result
    except asyncio.CancelledError:
        error = "Collection cancelled"
        raise
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        current_run.reset(token)
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat
        async with db.session() as session:
            events = (
                await session.execute(
                    sa.select(sa.func.count())
                    .select_from(Event)
                    .where(Event.run_id == run_id)
                )
            ).scalar_one()
            await session.execute(
                sa.update(Run)
                .where(Run.id == run_id)
                .values(
                    finished_at=utcnow(),
                    status="error" if error or result.processing_errors else "ok",
                    pages_crawled=result.pages_crawled,
                    pages_dead=result.pages_dead,
                    iocs_found=result.iocs_found,
                    new_alerts=result.new_alerts,
                    actors=result.actors,
                    processing_errors=result.processing_errors,
                    events_emitted=int(events),
                    error=error or (f"{result.processing_errors} page processing error(s)"
                                    if result.processing_errors else None),
                )
            )
            await session.commit()


def _humanize(seconds: float) -> str:
    """'26.2 hours', not '1570.3 minutes' — the unit a person would pick."""
    if seconds < 90:
        return f"{int(seconds)} second(s)"
    if seconds < 5400:
        return f"{seconds / 60:.0f} minute(s)"
    if seconds < 172_800:
        return f"{seconds / 3600:.1f} hour(s)"
    return f"{seconds / 86_400:.1f} day(s)"


def _is_stalled(run: Run) -> bool:
    """Crawled nothing while work was waiting."""
    return run.pages_crawled == 0 and (run.queued_at_start + run.due_at_start) > 0


async def list_runs(db: Database, limit: int = 20) -> list[dict]:
    async with db.session() as session:
        rows = (
            await session.execute(
                sa.select(Run).order_by(Run.started_at.desc(), Run.id.desc()).limit(limit)
            )
        ).scalars().all()
    return [
        {
            "id": r.id,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "duration_s": (
                round((_aware(r.finished_at) - _aware(r.started_at)).total_seconds(), 1)
                if r.finished_at and r.started_at else None
            ),
            "status": r.status,
            "trigger": r.trigger,
            "pages_crawled": r.pages_crawled,
            "pages_dead": r.pages_dead,
            "processing_errors": r.processing_errors or 0,
            "iocs_found": r.iocs_found,
            "events_emitted": r.events_emitted,
            "new_alerts": r.new_alerts,
            "actors": r.actors,
            "work_waiting": r.queued_at_start + r.due_at_start,
            "stalled": _is_stalled(r) if r.status == "ok" else False,
            "error": r.error,
        }
        for r in rows
    ]


async def health(db: Database, stale_after_s: int = 3600) -> dict:
    """Verdict on whether collection is working.

    ``unknown`` / ``ok`` / ``idle`` / ``stalled`` / ``failing``. Deliberately
    blunt: an operator should be able to read one word and know whether the feed
    is alive.
    """
    async with db.session() as session:
        # Abandoned passes are excluded from the verdict: they say a process was
        # restarted, not that collection is failing. They are still counted below,
        # because a worker that is *only* ever interrupted never collects anything.
        recent = (
            await session.execute(
                sa.select(Run)
                .where(Run.status.notin_(("running", "abandoned")))
                .order_by(Run.started_at.desc(), Run.id.desc())
                .limit(10)
            )
        ).scalars().all()
        running = (
            await session.execute(
                sa.select(sa.func.count()).select_from(Run).where(Run.status == "running")
            )
        ).scalar_one()
        abandoned = (
            await session.execute(
                sa.select(sa.func.count())
                .select_from(Run)
                .where(Run.status == "abandoned")
            )
        ).scalar_one()
        running_since = _aware(
            (
                await session.execute(
                    sa.select(sa.func.min(sa.func.coalesce(Run.heartbeat_at, Run.started_at)))
                    .where(Run.status == "running")
                )
            ).scalar_one()
        )

    if not recent and abandoned:
        return {
            "status": "unknown" if running else "failing",
            "detail": (
                "A pass is running, but every previous one was interrupted before "
                "it finished."
                if running
                else f"{abandoned} pass(es) were interrupted and none has ever "
                     "completed — the worker may be crash-looping or being killed."
            ),
            "in_progress": int(running),
            "consecutive_stalled": 0,
            "last_run": None,
        }

    if not recent:
        return {
            "status": "unknown",
            "detail": (
                # Don't tell someone to start the worker while the same response
                # reports one in flight.
                "First collection pass is in progress — no completed pass to report yet."
                if running
                else "No collection pass has been recorded yet. Run the worker "
                     "(`umbra worker`) or start a crawl."
            ),
            "in_progress": int(running),
            "consecutive_stalled": 0,
            "last_run": None,
        }

    last = recent[0]
    consecutive_stalled = 0
    for run in recent:
        if run.status == "ok" and _is_stalled(run):
            consecutive_stalled += 1
        else:
            break

    last_at = _aware(last.finished_at) or _aware(last.started_at)
    since = utcnow() - last_at
    last_summary = {
        "at": last_at.isoformat(),
        "minutes_ago": round(since.total_seconds() / 60, 1),
        "age": _humanize(since.total_seconds()),
        "pages_crawled": last.pages_crawled,
        "work_waiting": last.queued_at_start + last.due_at_start,
        "status": last.status,
    }

    waiting = last.queued_at_start + last.due_at_start
    running_for = (utcnow() - running_since).total_seconds() if running_since else 0.0
    if last.status == "error":
        status, detail = "failing", f"Last pass failed: {last.error}"
    elif not running and since.total_seconds() > stale_after_s:
        # The verdict below is drawn from the last *completed* pass, which stays
        # "ok" forever if the worker simply dies. Found the hard way: a worker
        # dead for 26 hours showed a green "Collecting" banner. A pass that
        # finished fine but long ago, with nothing in flight, means nobody is
        # collecting now — whatever the last one said.
        status = "stale"
        detail = (
            f"No collection pass has completed for {last_summary['age']} and none "
            "is in progress. The worker is not running — start it (`umbra worker`, "
            "or run-local.ps1)."
        )
    elif running and running_for > stale_after_s:
        status = "stale"
        detail = (
            f"A pass has been marked running for {_humanize(running_for)} with no "
            "completion — most likely the worker was killed without cleaning up. "
            "Restarting it reaps the stuck pass."
        )
    elif consecutive_stalled >= STALL_THRESHOLD:
        status = "stalled"
        detail = (
            f"{consecutive_stalled} consecutive passes fetched nothing while "
            f"{waiting} item(s) were waiting. Collection is not progressing — "
            "check the worker logs."
        )
    elif last.pages_crawled == 0 and waiting == 0:
        # Only claim "idle" when it is actually true that there was nothing to do.
        # Saying it while work is queued would make the explanation contradict the
        # data, which is a faster way to lose trust than showing no status at all.
        status = "idle"
        detail = (
            "Last pass fetched nothing, and nothing was waiting — the frontier is "
            "drained and no page is due for recrawl yet. Seed more sites to continue."
        )
    elif last.pages_crawled == 0:
        # One quiet pass with work queued is not yet a fault: every queued link may
        # belong to a host that is currently failing and backing off. Reported
        # plainly so a developing stall is visible before it trips the threshold.
        status = "ok"
        detail = (
            f"Last pass fetched nothing while {waiting} item(s) were waiting. Not yet "
            "a fault — hosts in failure backoff can do this — but a second such pass "
            "will be reported as stalled."
        )
    else:
        status = "ok"
        detail = f"Last pass fetched {last.pages_crawled} page(s) {last_summary['age']} ago."

    return {
        "status": status,
        "detail": detail,
        "in_progress": int(running),
        "consecutive_stalled": consecutive_stalled,
        "last_run": last_summary,
        "recent_pages": [r.pages_crawled for r in recent],
    }


async def purge_old_runs(db: Database, keep_days: int = 30) -> int:
    """Trim the run log. It is operational telemetry, not intelligence."""
    cutoff = utcnow() - dt.timedelta(days=keep_days)
    async with db.session() as session:
        result = await session.execute(sa.delete(Run).where(Run.started_at < cutoff))
        await session.commit()
    return int(result.rowcount or 0)
