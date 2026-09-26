"""Retention/purge tests."""

import datetime as dt

import sqlalchemy as sa

from umbra.db import Database
from umbra.models import Credential, Embedding, Ioc, Page, utcnow
from umbra.retention import purge_expired


async def test_purge_expired_cascades(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'r.db'}")
    await db.create_all()
    old = utcnow() - dt.timedelta(days=10)
    async with db.session() as s:
        s.add(Page(url="http://old.onion/", status="crawled", created_at=old,
                   blocked=False, stored_content=True))
        s.add(Ioc(page_url="http://old.onion/", ioc_type="btc", value="X"))
        s.add(Credential(page_url="http://old.onion/", email="a@b.com"))
        s.add(Embedding(page_url="http://old.onion/", model="m", dim=1, vector=b"\x00\x00\x00\x00"))
        s.add(Page(url="http://new.onion/", status="crawled", blocked=False, stored_content=True))
        await s.commit()

    result = await purge_expired(db, retention_days=7)
    assert result["purged_pages"] == 1

    async with db.session() as s:
        urls = set((await s.execute(sa.select(Page.url))).scalars())
        assert urls == {"http://new.onion/"}
        # derived records for the purged page are gone
        assert (await s.execute(sa.select(sa.func.count()).select_from(Ioc))).scalar() == 0
        assert (await s.execute(sa.select(sa.func.count()).select_from(Credential))).scalar() == 0
        assert (await s.execute(sa.select(sa.func.count()).select_from(Embedding))).scalar() == 0

    # 0 days = retention disabled -> no-op
    assert (await purge_expired(db, 0))["purged_pages"] == 0
    await db.dispose()
