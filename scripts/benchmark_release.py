"""Repeatable local throughput, search-memory and synthetic relevance benchmark."""
import argparse
import asyncio
import json
import platform
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

import sqlalchemy as sa

from umbra.config import Settings
from umbra.crawl.scheduler import Scheduler, CrawlItem
from umbra.db import Database
from umbra.intel.embeddings import HashingEmbedder, search, to_bytes
from umbra.models import Page, Embedding


async def run(pages=5000, links=200):
    with tempfile.TemporaryDirectory(prefix="umbra-bench-") as directory:
        root = Path(directory)
        timing = {"individual": [], "batch": []}
        for repeat in range(3):
            for mode in timing:
                settings = Settings(_env_file=None,
                    database_url=f"sqlite+aiosqlite:///{(root/f'{mode}{repeat}.db').as_posix()}",
                    max_pages_per_domain=0)
                db = Database(settings.database_url)
                await db.create_all()
                scheduler = Scheduler(db, settings)
                items = [CrawlItem(f"http://fixture.onion/{i}") for i in range(links)]
                start = time.perf_counter()
                if mode == "batch":
                    count = await scheduler.add_many(items)
                else:
                    count = sum([await scheduler.add(i) for i in items])
                timing[mode].append(time.perf_counter()-start)
                assert count == links
                await db.dispose()
        db = Database(f"sqlite+aiosqlite:///{(root/'search.db').as_posix()}")
        await db.create_all()
        embedder = HashingEmbedder(128)
        topics = ["notebook paper stationery", "tomatoes gardening compost", "bicycle repair wheels",
                  "database software backup", "cooking recipes bread"]
        vectors = [to_bytes(embedder.embed(t)) for t in topics]
        async with db.session() as s:
            for start in range(0, pages, 500):
                rows = [{"url":f"http://fixture.onion/{i:08}","title":topics[i%5],
                         "content":topics[i%5], "status":"crawled", "blocked":False}
                        for i in range(start,min(start+500,pages))]
                await s.execute(sa.insert(Page),rows)
                await s.execute(sa.insert(Embedding),[{
                    "page_url":r["url"],"model":embedder.name,"dim":128,
                    "vector":vectors[(start+j)%5]} for j,r in enumerate(rows)])
            await s.commit()
        latencies, precision, peaks = [], [], []
        for query, expected in zip(["notebook", "gardening", "bicycle", "database", "bread"], topics):
            tracemalloc.start()
            start=time.perf_counter()
            results=await search(db,embedder,query,10)
            latencies.append(time.perf_counter()-start)
            _, peak=tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peaks.append(peak)
            precision.append(sum(r["title"]==expected for r in results)/len(results))
        await db.dispose()
        individual, batch = (statistics.median(timing[k]) for k in ("individual","batch"))
        return {"platform":platform.platform(),"python":platform.python_version(),
                "enqueue":{"links":links,"repeats":3,"individual_seconds":individual,
                           "batch_seconds":batch,"speedup":individual/batch},
                "search":{"pages":pages,"model":embedder.name,"queries":5,
                          "median_seconds":statistics.median(latencies),
                          "max_python_allocated_bytes":max(peaks),
                          "mean_precision_at_10":statistics.mean(precision)},
                "limits":"Synthetic SQLite benchmark. Python allocation tracking excludes native "
                         "model/runtime memory; local semantic model and Tor throughput are not measured. "
                         "Relevance scores reflect obvious synthetic topics, not live-corpus accuracy."}


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--pages",type=int,default=5000)
    parser.add_argument("--links",type=int,default=200)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    report=json.dumps(asyncio.run(run(args.pages,args.links)),indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(report,encoding="utf-8")
    print(report)
