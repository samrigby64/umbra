"""Bounded synthetic crawler endurance test; never contacts source sites.

Run with the project Python, --directory in durable user storage, --hours 48.
Each cycle uses the same database. STOP file requests a graceful stop.
Long sampling gaps are recorded: suspended time does not earn test coverage.
"""
import argparse
import asyncio
import json
import logging
import os
import time
from pathlib import Path

import psutil
import sqlalchemy as sa

from umbra.config import Settings
from umbra.db import Database
from umbra.crawl.crawler import Crawler
from umbra.crawl.scorer import KeywordScorer
from umbra.compliance.policy import CompliancePolicy
from umbra.enrich.ioc import IocExtractor
from umbra.fetch.client import FetchResult
from umbra.models import Page, PageVersion


async def main(args):
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    database = directory / "soak.db"
    if database.exists():
        raise ValueError("Use a new directory per run; never overwrite an earlier soak.")
    settings = Settings(_env_file=None, database_url="sqlite+aiosqlite:///"+database.as_posix(),
                        use_tor=False, allow_clearnet=True, strict_scope=True,
                        max_pages=32, max_pages_per_domain=32, max_depth=0, max_workers=4, versions_per_page=3,
                        embedder_kind="hashing", embeddings_enabled=False,
                        backup_interval_hours=0, store_html=True)
    db = Database(settings.database_url)
    await db.create_all()
    started = time.time()
    covered = 0.0
    previous = started
    cycles = 0
    errors = 0
    gaps = 0
    process = psutil.Process()
    report = {"pid": os.getpid(), "started_at": started, "target_hours": args.hours,
              "scope": "Synthetic crawler and SQLite endurance; not live Tor availability",
              "status": "running"}

    class Fetcher:
        async def fetch(self, url):
            await asyncio.sleep(.002)
            if cycles % 7 == 6 and url.endswith("/0"):
                return FetchResult(url=url, ok=False, error="Injected transport timeout")
            body = (f"<html><body><p>Fictional vendor observation {cycles % 4} "
                    f"{url.rsplit('/', 1)[-1]}</p></body></html>").encode()
            return FetchResult(url=url, ok=True, status=200, body=body,
                               text=body.decode(), content_type="text/html")

    try:
        while covered < args.hours * 3600 and not (directory/"STOP").exists():
            now = time.time()
            delta = now-previous
            if delta > max(120, args.interval*3):
                gaps += 1
            else:
                covered += max(0, delta)
            previous = now
            crawler = Crawler(settings, db, Fetcher(), KeywordScorer([]),
                              CompliancePolicy(store_html=True), [IocExtractor()])
            stats = await asyncio.wait_for(crawler.run(
                [f"https://fixture.example/{i}" for i in range(32)], force_seeds=True), 90)
            errors += stats.get("processing_errors", 0)
            async with db.session() as s:
                pages = await s.scalar(sa.select(sa.func.count()).select_from(Page))
                versions = await s.scalar(sa.select(sa.func.count()).select_from(PageVersion))
            if pages != 32 or versions > 96:
                raise AssertionError(f"Unbounded rows: pages={pages}, versions={versions}")
            cycles += 1
            report.update(cycles=cycles, covered_hours=covered/3600, wall_hours=(now-started)/3600,
                          gaps=gaps, processing_errors=errors, pages=pages, versions=versions,
                          rss_bytes=process.memory_info().rss,
                          database_bytes=sum(p.stat().st_size for p in directory.glob("soak.db*")),
                          sampled_at=time.time())
            with (directory/"metrics.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(report)+"\n")
            pending = directory/"status.tmp"
            pending.write_text(json.dumps(report, indent=2), encoding="utf-8")
            pending.replace(directory/"status.json")
            if covered < args.hours*3600:
                await asyncio.sleep(args.interval)
        report["status"] = "completed" if covered >= args.hours*3600 and not errors else "incomplete"
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        await db.dispose()
        (directory/"status.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--hours", type=float, default=48)
    parser.add_argument("--interval", type=float, default=30)
    args = parser.parse_args()
    if args.hours <= 0 or args.interval <= 0:
        parser.error("Hours and interval must be positive")
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main(args))
