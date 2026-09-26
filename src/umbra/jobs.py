"""Durable, bounded collection schedules. A live API process runs due jobs.

The page frontier is shared across the installation; exact host scope is explicit.
Database leases fence job completion and allow recovery after process loss.
"""
import asyncio
import contextlib
import datetime as dt
import json

import sqlalchemy as sa

from .factory import build_crawler
from .logging import get_logger
from .models import CollectionJob, utcnow
from .runs import record_run

log = get_logger("jobs")
LEASE_SECONDS = 90


def describe(job):
    return {k: getattr(job, k) for k in (
        "id", "name", "interval_s", "paused", "next_run_at", "lease_until",
        "status", "stop_reason", "updated_at"
    )} | {"config": json.loads(job.config), "last_result": json.loads(job.last_result)}


async def claim(db):
    async with db.write_session() as s:
        now = utcnow()
        # One scheduled job at a time across API processes, to keep budgets predictable.
        if await s.scalar(sa.select(CollectionJob.id).where(
            CollectionJob.lease_until > now
        ).limit(1)):
            return None
        job = await s.scalar(sa.select(CollectionJob).where(
            CollectionJob.paused.is_(False), CollectionJob.next_run_at <= now
        ).order_by(CollectionJob.next_run_at, CollectionJob.id).limit(1))
        if not job:
            return None
        job.claim_seq += 1
        job.lease_until = now + dt.timedelta(seconds=LEASE_SECONDS)
        job.status = "running"
        job.updated_at = now
        await s.commit()
        return job


async def finish(db, job, result, reason, error=False):
    async with db.write_session() as s:
        row = await s.get(CollectionJob, job.id)
        if not row or row.claim_seq != job.claim_seq:
            return False
        row.lease_until = None
        row.last_result = json.dumps(result)
        row.stop_reason = reason
        row.updated_at = utcnow()
        if row.paused:
            reason = row.stop_reason = "paused"
        if row.paused or row.interval_s == 0:
            row.paused = True
            row.next_run_at = None
            row.status = "error" if error else "paused" if reason == "paused" else "completed"
        else:
            row.next_run_at = utcnow() + dt.timedelta(seconds=row.interval_s)
            row.status = "error" if error else "scheduled"
        await s.commit()
        return True


async def execute(db, settings, job, builder=build_crawler):
    config = json.loads(job.config)
    run_settings = settings.model_copy(update={k: v for k, v in config.items()
                                               if k not in ("seeds", "max_duration_s")})
    # Page claims must expire before the job lease, or a recovered one-shot job
    # could see no eligible work and finish while abandoned pages remain locked.
    run_settings.reclaim_after_s = min(settings.reclaim_after_s, LEASE_SECONDS-10)
    crawler, fetcher = await asyncio.to_thread(builder, run_settings, db)
    lost_lease = False

    async def heartbeat():
        nonlocal lost_lease
        while True:
            await asyncio.sleep(10)
            async with db.write_session() as s:
                row = await s.get(CollectionJob, job.id)
                if not row or row.claim_seq != job.claim_seq:
                    lost_lease = True
                    crawler.request_stop()
                    return
                if row.paused:
                    crawler.request_stop()
                row.lease_until = utcnow() + dt.timedelta(seconds=LEASE_SECONDS)
                await s.commit()

    pulse = asyncio.create_task(heartbeat())
    result = {}
    reason, error = "no_eligible_pages_in_scope", False
    try:
        async with record_run(db, trigger="job", settings=run_settings) as run:
            try:
                async with asyncio.timeout(config["max_duration_s"]):
                    result = await crawler.run(config["seeds"], force_seeds=False)
                    from .alerting import evaluate_watchlists
                    from .intel.entities import resolve_actors
                    alerts = await evaluate_watchlists(db)
                    actors = await resolve_actors(db)
                    result["new_alerts"] = alerts["new_alerts"]
                    result["actors"] = actors["actors"]
                    run.new_alerts = alerts["new_alerts"]
                    run.actors = actors["actors"]
            finally:
                result.update(await crawler.stats())
                for field, key in (("pages_crawled", "crawled"), ("pages_dead", "dead"),
                                   ("iocs_found", "iocs"), ("processing_errors", "processing_errors")):
                    setattr(run, field, result.get(key, 0))
        reason = result.get("stop_reason", reason)
        if lost_lease:
            reason = "lease_lost"
    except TimeoutError:
        result.update(await crawler.stats())
        reason = "time_budget_reached"
    except asyncio.CancelledError:
        # Keep the due time and lease: a new process reclaims it after expiry.
        raise
    except Exception as exc:
        reason, error = "collection_error", True
        result["error_type"] = type(exc).__name__
        log.exception("Collection job %s failed", job.id)
    finally:
        pulse.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await pulse
        await fetcher.aclose()
    await finish(db, job, result, reason, error)


async def loop(db, settings):
    while True:
        try:
            job = await claim(db)
            if job:
                try:
                    await execute(db, settings, job)
                except Exception as exc:
                    await finish(db, job, {"error_type": type(exc).__name__},
                                 "initialisation_failed", True)
                    log.exception("Job initialisation failed")
            else:
                await asyncio.sleep(3)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Job scheduler error; retrying")
            await asyncio.sleep(10)
