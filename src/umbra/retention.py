"""Data retention — purge pages (and everything derived from them) past a window.

Dark-web corpora accumulate sensitive material; a retention policy that actually
deletes is a compliance requirement, not a nicety. ``purge_expired`` hard-deletes
pages older than ``retention_days`` along with their IOCs, credentials, listings,
embeddings, and alerts. Run it on a schedule (``umbra purge``).
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa

from .db import Database
from .logging import get_logger
from .models import Alert, Credential, Embedding, Ioc, Listing, Page, PageVersion, utcnow

log = get_logger("retention")

# Per-page tables to cascade the delete across (Page itself deleted last).
_CASCADE = (Ioc, Credential, Listing, Embedding, Alert, PageVersion)


async def purge_expired(db: Database, retention_days: int, batch: int = 1000) -> dict:
    """Delete pages older than ``retention_days`` and all their derived records."""
    if retention_days <= 0:
        return {"purged_pages": 0}
    cutoff = utcnow() - dt.timedelta(days=retention_days)

    purged = 0
    while True:
        async with db.session() as session:
            urls = (
                await session.execute(
                    sa.select(Page.url).where(Page.created_at < cutoff).limit(batch)
                )
            ).scalars().all()
            if not urls:
                break
            for table in _CASCADE:
                await session.execute(sa.delete(table).where(table.page_url.in_(urls)))
            await session.execute(sa.delete(Page).where(Page.url.in_(urls)))
            await session.commit()
            purged += len(urls)

    if purged:
        log.info("purged %d expired page(s) (older than %d days)", purged, retention_days)
    return {"purged_pages": purged}
