"""Isolated GUI test server with synthetic data; never starts a crawl worker."""
import asyncio
import hashlib
import os
from pathlib import Path

import uvicorn

from umbra.api.app import create_app
from umbra.config import Settings
from umbra.crawl.scheduler import Scheduler, CrawlItem
from umbra.db import Database
from umbra.intel.embeddings import HashingEmbedder, to_bytes
from umbra.models import Page, Ioc, utcnow

database = Path(os.environ["TEMP"]) / "umbra-release-040-preview.db"
settings = Settings(_env_file=None, database_url=f"sqlite+aiosqlite:///{database.as_posix()}",
                    embedder_kind="hashing", embedding_dim=128, use_tor=False, preview_mode=True)


async def seed():
    db = Database(settings.database_url)
    await db.create_all()
    scheduler = Scheduler(db, settings)
    await scheduler.load()
    url = "https://fixture.example/vendor"
    async with db.session() as s:
        present = await s.get(Page, url)
    if present is not None:
        await db.dispose()
        return
    await scheduler.add(CrawlItem(url))
    for price in (12, 15):
        body = f"<p>Vendor: ExampleSeller</p><p>Notebook ${price}</p>".encode()
        text = f"Vendor: ExampleSeller\nNotebook ${price}"
        page = Page(url=url, hostname="fixture.example", title="Synthetic notebook listing",
                    status="crawled", content=text, html=body.decode(), raw_body=body,
                    body_truncated=False, content_sha256=hashlib.sha256(body).hexdigest(),
                    content_length=len(body), fetched_at=utcnow(), final_url=url,
                    depth=0, score=1, blocked=False, stored_content=True, http_status=200)
        await scheduler.complete(page, [Ioc(page_url=url, ioc_type="handle", value="ExampleSeller",
                                           context="Vendor: ExampleSeller"),
                                       Ioc(page_url=url, ioc_type="contact_email",
                                           value="seller@example.org", context="Contact seller@example.org")],
                                 ("hashing-128", 128, to_bytes(HashingEmbedder(128).embed(text))))
    await db.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
    uvicorn.run(create_app(settings), host="127.0.0.1", port=8767)
