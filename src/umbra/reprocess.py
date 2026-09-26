"""Re-derive everything from already-stored pages, without re-fetching anything.

Whenever an extractor or embedding model improves, the corpus you already
collected is out of date. Re-crawling to fix it is slow, hammers hidden services,
and can't even reproduce pages that have since gone offline. This replays the
enrichers and the embedder against the stored page text instead — seconds instead
of hours, and no network traffic.
"""

from __future__ import annotations

import sqlalchemy as sa
import asyncio
import json

from .crawl.parse import ParsedPage, parse_page
from .db import Database
from .intel.embeddings import Embedder, to_bytes
from .logging import get_logger
from .models import STATUS_CRAWLED, STATUS_DISCOVERED, Credential, Embedding, Ioc, Listing, Page

log = get_logger("reprocess")

_DERIVED = (Ioc, Credential, Listing)

_EMBED_BATCH = 50


async def reprocess_pages(db: Database, enrichers: list, limit: int | None = None) -> dict:
    """Re-extract from every crawled page that still has stored content."""
    async with db.session() as session:
        stmt = sa.select(Page.url).where(
            Page.status == STATUS_CRAWLED, Page.content.isnot(None)
        )
        if limit:
            stmt = stmt.limit(limit)
        urls = (await session.execute(stmt)).scalars().all()

    pages_done = 0
    records_total = 0
    for url in urls:
        async with db.session() as session:
            page = (
                await session.execute(sa.select(Page).where(Page.url == url))
            ).scalar_one_or_none()
        if page is None or not page.content or page.blocked:
            continue
        parsed = (await asyncio.to_thread(parse_page, page.html, page.final_url or url)
                  if page.html else ParsedPage(url=url, text=page.content))
        records: list = []
        errors = []
        failed_tables = set()
        for enricher in enrichers:
            try:
                records.extend(await enricher.enrich(page, parsed))
            except Exception as exc:
                name = getattr(enricher, "name", "?")
                errors.append({"extractor": name, "error_type": type(exc).__name__})
                failed_tables.add({"ioc": Ioc, "listings": Listing,
                                   "credentials": Credential}.get(name))
                log.exception("enricher %s failed on %s", name, url)
        async with db.write_session() as session:
            current = await session.get(Page, url)
            if not current or current.blocked or current.status == "in_progress" or (
                current.content_sha256 != page.content_sha256
            ):
                continue  # A concurrent crawl/policy action superseded this input.
            current.extraction_errors = json.dumps(errors)
            for table in _DERIVED:
                if table not in failed_tables:
                    await session.execute(sa.delete(table).where(table.page_url == url))
            for record in records:
                session.add(record)
            await session.commit()
            pages_done += 1
            records_total += len(records)

    log.info("reprocessed %d page(s) -> %d record(s)", pages_done, records_total)
    return {"pages": pages_done, "records": records_total}


async def rescore_frontier(
    db: Database, scorer, limit: int | None = None, *, off_host_factor: float = 0.1
) -> dict:
    """Recompute priorities for links that are queued but not yet fetched.

    ``Page.score`` is written once, when a link is discovered, and never revisited
    — so improving the scorer only affects links found *after* the change. A
    frontier built earlier keeps whatever priority it was born with, which in
    practice means a uniform 1.0 and no prioritisation at all. Observed directly:
    with the structural prior live, the crawler still fetched ``login.php`` and
    ``register.php`` back to back, because those rows were queued before it
    existed.

    Only ever touches never-fetched pages. Rewriting the score of something
    already crawled would reorder recrawls on a basis that has nothing to do with
    how the page actually turned out.
    """
    from .crawl.parse import DiscoveredLink
    from .crawl.scorer import prioritise

    async with db.session() as session:
        pinned_hosts = set(
            (
                await session.execute(
                    sa.select(Page.hostname)
                    .where(Page.pinned.is_(True), Page.hostname.isnot(None))
                    .distinct()
                )
            ).scalars()
        )
        stmt = sa.select(Page.url, Page.depth, Page.score, Page.targeted).where(
            Page.status == STATUS_DISCOVERED
        )
        if limit:
            stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).all()

        changed = 0
        for url, depth, old, targeted in rows:
            new = prioritise(
                scorer, DiscoveredLink(url=url, anchor_text=""), depth or 0,
                targeted=bool(targeted),
                pinned_hosts=pinned_hosts,
                off_host_factor=off_host_factor,
            )
            if old is None or abs(new - old) > 1e-9:
                await session.execute(
                    sa.update(Page).where(Page.url == url).values(score=new)
                )
                changed += 1
        await session.commit()

    log.info("rescored %d of %d queued link(s)", changed, len(rows))
    return {"queued": len(rows), "rescored": changed}


async def embedding_coverage(db: Database, embedder: Embedder) -> dict:
    """Report how much of the corpus is searchable *by the current embedder*.

    Search compares only vectors of matching dimension, so a corpus embedded by a
    previous model isn't wrong — it is invisible. Without this the symptom is an
    empty result list, which looks identical to "nothing matched" and sends you
    hunting for a query bug that doesn't exist.
    """
    async with db.session() as session:
        pages = (
            await session.execute(
                sa.select(sa.func.count())
                .select_from(Page)
                .where(Page.status == STATUS_CRAWLED, Page.content.isnot(None))
            )
        ).scalar_one()
        rows = (
            await session.execute(
                sa.select(Embedding.model, Embedding.dim, sa.func.count())
                .join(Page, Page.url == Embedding.page_url)
                .where(Page.blocked.is_(False), Page.content.isnot(None))
                .group_by(Embedding.model, Embedding.dim)
            )
        ).all()

    by_model = [{"model": m, "dim": d, "pages": n} for m, d, n in rows]
    usable = sum(n for m, d, n in rows if d == embedder.dim and m == embedder.name)
    return {
        "embedder": embedder.name,
        "dim": embedder.dim,
        "pages_with_content": pages,
        "searchable_now": usable,
        "stale": sum(n for m, d, n in rows if d != embedder.dim or m != embedder.name),
        "by_model": by_model,
    }


async def reembed_pages(db: Database, embedder: Embedder, limit: int | None = None) -> dict:
    """Rebuild embeddings for stored pages using the current embedder.

    Needed whenever the embedder changes: vectors are compared by dimension, so
    the old ones simply stop participating in search. Like ``reprocess_pages``
    this reads stored text — no re-crawling.
    """
    async with db.session() as session:
        stmt = sa.select(Page.url).where(
            Page.status == STATUS_CRAWLED, Page.content.isnot(None)
        )
        if limit:
            stmt = stmt.limit(limit)
        urls = (await session.execute(stmt)).scalars().all()

    done = 0
    for start in range(0, len(urls), _EMBED_BATCH):
        batch = urls[start : start + _EMBED_BATCH]
        async with db.session() as session:
            pages = (
                await session.execute(sa.select(Page.url, Page.content, Page.content_sha256)
                                      .where(Page.url.in_(batch)))
            ).all()
        for page in pages:
            if not page.content:
                continue
            vector = await asyncio.to_thread(embedder.embed, page.content)
            async with db.write_session() as session:
                current = (await session.execute(sa.select(Page.content_sha256, Page.content)
                    .where(Page.url == page.url, Page.blocked.is_(False)))).first()
                if current is None or current.content_sha256 != page.content_sha256 or current.content != page.content:
                    continue  # recrawled/purged while inference was in flight
                await session.execute(
                    sa.delete(Embedding).where(Embedding.page_url == page.url)
                )
                session.add(
                    Embedding(
                        page_url=page.url,
                        model=embedder.name,
                        dim=embedder.dim,
                        vector=to_bytes(vector),
                    )
                )
                done += 1
                await session.commit()

    log.info("re-embedded %d page(s) with %s", done, embedder.name)
    return {"pages": done, "embedder": embedder.name, "dim": embedder.dim}
