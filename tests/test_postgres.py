"""Runs against a dedicated test database, never the operator's configured DB."""
import asyncio
import os

import httpx
import pytest
import sqlalchemy as sa

from umbra.access import audit
from umbra.api import create_app
from umbra.config import Settings
from umbra.crawl.scheduler import Scheduler
from umbra.db import Database
from umbra.models import AuditEntry, Page, utcnow

pytestmark = pytest.mark.skipif(not os.environ.get("UMBRA_TEST_POSTGRES_URL"),
                                reason="Dedicated PostgreSQL test database not configured")


async def test_postgres_migration_frontier_search_case_and_audit():
    url = os.environ["UMBRA_TEST_POSTGRES_URL"]
    settings = Settings(_env_file=None, database_url=url, embedder_kind="hashing",
                        use_tor=False, strict_scope=True, allowed_hosts=["fixture.example"],
                        backup_interval_hours=0)
    db, second = Database(url), Database(url)
    await asyncio.gather(db.create_all(), second.create_all())
    scheduler = Scheduler(db, settings)
    await scheduler.load()
    seed = "https://fixture.example/postgres"
    await scheduler.seed([seed], force=True)
    claims = await asyncio.gather(scheduler.claim(), Scheduler(second, settings).claim())
    item = next(c for c in claims if c)
    assert sum(c is not None for c in claims) == 1
    page = Page(url=seed, hostname="fixture.example", depth=0, score=1, status="crawled",
                content="Synthetic PostgreSQL notebook evidence", title="Notebook",
                content_sha256="a"*64, blocked=False, stored_content=True,
                body_truncated=False, fetched_at=utcnow())
    await scheduler.complete(page, [], claim_token=item.claim_token)
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                base_url="http://test") as c:
        assert (await c.get("/workspace/search", params={"q": "notebook"})).json()["total"] >= 1
        assert (await c.get("/collection/quality")).json()["retained_pages"] >= 1
        case = await c.post("/cases", json={"name": "Postgres synthetic test"})
        assert case.status_code == 200, case.text
        assert (await c.get("/cases/"+str(case.json()["id"]))).status_code == 200
        job = await c.post("/collection/jobs", json={"name": "PG paused", "seeds": [seed]})
        assert job.status_code == 200, job.text
        assert (await c.get("/audit/verify")).json()["valid"]
    async with db.write_session() as s:
        await audit(s, "test", "postgres_validated", {})
        await s.commit()
    async with db.session() as s:
        with pytest.raises(sa.exc.DBAPIError, match="append-only"):
            await s.execute(sa.update(AuditEntry).values(action="changed"))
        await s.rollback()
    await db.dispose()
    await second.dispose()
