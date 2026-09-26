"""Database-backed, resumable crawl frontier with recrawl scheduling.

The ``pages`` table is the single source of truth for the frontier, so a crawl
**resumes exactly where it left off** after a restart — no state is held only in
memory. Two in-memory caches (the seen-URL set and per-domain counts) are
rehydrated from the DB in :meth:`Scheduler.load` purely to make enqueue checks
cheap; the primary-key constraint is the backstop.

Frontier read/modify/write operations use database transaction locks across
processes. SQLite reserves the writer before reading; PostgreSQL uses a
transaction-scoped advisory lock. Network and model work run outside these locks.

Failure handling is careful by design: a transient fetch failure never destroys
previously-archived content and never silently drops a page — it preserves the
last-known-good content and retries with backoff, only marking the page dead
after ``max_fetch_failures`` consecutive failures.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass

import sqlalchemy as sa

from .. import timeline
from ..config import Settings
from ..db import Database
from ..scope import allows, valid_host
from ..versions import retain_version, snapshot
from ..intel.entities import STRONG_TYPES
from ..logging import get_logger
from ..models import (
    STATUS_CRAWLED,
    STATUS_DEAD,
    STATUS_DISCOVERED,
    STATUS_IN_PROGRESS,
    Credential,
    Embedding,
    Ioc,
    Listing,
    Page,
    PageVersion,
    utcnow,
)
from .parse import hostname

log = get_logger("scheduler")

# Per-page derived records that entity/enrichment passes produce. On a content
# change these are all replaced (delete + re-insert) so they reflect the current
# page version rather than accumulating across recrawls.
_DERIVED_TABLES = (Ioc, Credential, Listing)

# Fields copied from the crawler's transient Page onto the persisted row on a
# *successful* fetch whose content changed. Deliberately excludes recrawl/failure
# bookkeeping, which the scheduler owns.
_RESULT_FIELDS = (
    "parent_url", "hostname", "depth", "score", "status", "http_status",
    "title", "description", "keywords", "language", "content", "html",
    "content_sha256", "content_length", "stored_content", "blocked",
    "block_reason", "error", "fetched_at", "page_type", "threat_category", "summary",
    "raw_body", "body_truncated", "final_url", "capture_metadata", "extraction_errors",
)


@dataclass(order=False)
class CrawlItem:
    url: str
    depth: int = 0
    parent: str | None = None
    score: float = 1.0
    claim_token: int = 0  # ownership token (see Scheduler.complete)
    targeted: bool = False  # reached from a pinned seed; inherited by children


class Scheduler:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._seen: set[str] = set()
        self._domain_counts: dict[str, int] = {}
        self._pinned_hosts: set[str] = set()
        self._claim_lock = asyncio.Lock()

    @property
    def pinned_hosts(self) -> set[str]:
        """Hosts the operator chose as targets; links off them are demoted."""
        return self._pinned_hosts

    async def load(self) -> None:
        """Rehydrate the in-memory caches from the DB (enables resume)."""
        async with self.db.session() as session:
            self._seen = set((await session.execute(sa.select(Page.url))).scalars())
            rows = (
                await session.execute(
                    sa.select(Page.hostname, sa.func.count()).group_by(Page.hostname)
                )
            ).all()
            self._domain_counts = {host: n for host, n in rows if host}
            self._pinned_hosts = set(
                (
                    await session.execute(
                        sa.select(Page.hostname)
                        .where(Page.pinned.is_(True), Page.hostname.isnot(None))
                        .distinct()
                    )
                ).scalars()
            )
        if self._seen:
            log.info("resumed: %d known urls, %d domains", len(self._seen), len(self._domain_counts))

    async def seed(self, urls: list[str], force: bool = False, pin: bool = False) -> int:
        """Enqueue seed URLs; returns how many are queued to crawl.

        ``force=True`` means "the user explicitly asked for these now" (the GUI
        Start button / ``umbra crawl``): a seed we've seen before is reset to be
        due immediately. Without it, re-submitting a URL that previously failed —
        or was crawled recently — would be silently skipped until its backoff
        expired, which looks like the crawler doing nothing.

        ``pin=True`` marks the seeds as targets: the crawl stays on their hosts
        (off-host links demoted, larger per-host budget). Source packs always pin.
        """
        queued = 0
        for url in urls:
            item = CrawlItem(url=url, depth=0, parent=None, score=1.0, targeted=pin)
            if await self.add(item):
                queued += 1
            elif force and await self._force_due(url):
                queued += 1
            if pin:
                await self._pin(url)
        return queued

    # Everything discovered beneath a seed, at any depth. Used to mark an
    # existing lineage as targeted when a seed is pinned after the fact — a pack
    # re-applied to a frontier that was built before pinning existed, say.
    _LINEAGE_UPDATE = sa.text(
        """
        WITH RECURSIVE lineage(url) AS (
            SELECT url FROM pages WHERE url = :seed
            UNION
            SELECT p.url FROM pages p JOIN lineage l ON p.parent_url = l.url
        )
        UPDATE pages SET targeted = :yes WHERE url IN (SELECT url FROM lineage)
        """
    )

    async def _pin(self, url: str) -> None:
        async with self.db.write_session() as session:
            await session.execute(
                sa.update(Page).where(Page.url == url).values(pinned=True, targeted=True)
            )
            await session.execute(self._LINEAGE_UPDATE, {"seed": url, "yes": True})
            await session.commit()
        host = hostname(url)
        if host:
            self._pinned_hosts.add(host)

    async def _force_due(self, url: str) -> bool:
        """Make an already-known URL claimable right now. Returns True if reset."""
        async with self.db.write_session() as session:
            row = (
                await session.execute(sa.select(Page).where(Page.url == url))
            ).scalar_one_or_none()
            if row is None or row.status == STATUS_IN_PROGRESS:
                return False  # don't disturb a page another worker is fetching
            row.status = STATUS_CRAWLED if row.content_sha256 else STATUS_DISCOVERED
            row.next_crawl_at = utcnow()
            row.consecutive_failures = 0
            row.processing_failures = 0
            row.depth, row.parent_url = 0, None
            await session.commit()
            return True

    async def add(self, item: CrawlItem) -> bool:
        return bool(await self.add_many([item]))

    async def add_many(self, items: list[CrawlItem]) -> int:
        """One transaction per bounded batch; DB counts enforce caps across processes."""
        added = 0
        for start in range(0, len(items), 200):
            batch = items[start:start + 200]
            async with self.db.write_session() as session:
                hosts = {valid_host(i.url) for i in batch}
                counts = dict((await session.execute(sa.select(
                    Page.hostname, sa.func.count()
                ).where(Page.hostname.in_(hosts)).group_by(Page.hostname))).all())
                known_rows = (await session.execute(sa.select(Page).where(
                    Page.url.in_([i.url for i in batch])
                ))).scalars().all()
                known = {p.url for p in known_rows}
                existing = {p.url: p for p in known_rows}
                for item in batch:
                    if item.depth > self.settings.max_depth:
                        continue
                    if not allows(item.url, self.settings.allowed_hosts):
                        continue
                    if item.url in known:
                        prior = existing.get(item.url)
                        if prior and prior.status != STATUS_IN_PROGRESS and item.depth < prior.depth:
                            prior.depth, prior.parent_url = item.depth, item.parent
                        continue
                    host = valid_host(item.url)
                    cap = (self.settings.max_pages_per_domain_pinned
                           if host in self._pinned_hosts else self.settings.max_pages_per_domain)
                    if cap and counts.get(host, 0) >= cap:
                        continue
                    session.add(Page(
                        url=item.url, parent_url=item.parent, hostname=host, depth=item.depth,
                        score=item.score, targeted=item.targeted, status=STATUS_DISCOVERED,
                        next_crawl_at=utcnow(),
                    ))
                    known.add(item.url)
                    counts[host] = counts.get(host, 0) + 1
                    added += 1
                await session.commit()
        return added

    async def prior_content_sha(self, url: str) -> str | None:
        async with self.db.session() as session:
            return (
                await session.execute(sa.select(Page.content_sha256).where(Page.url == url))
            ).scalar_one_or_none()

    async def claim(self) -> CrawlItem | None:
        """Atomically claim the highest-priority eligible page.

        Eligible = discovered/crawled with ``next_crawl_at`` due, or an
        ``in_progress`` row whose worker appears to have died (stale claim).
        """
        now = utcnow()
        stale_before = now - dt.timedelta(seconds=self.settings.reclaim_after_s)
        async with self._claim_lock:
            async with self.db.write_session() as session:
                stmt = (
                    sa.select(Page)
                    .where(
                        sa.or_(
                            # discovered / crawled / retrying-dead, once due.
                            # (permanent-dead rows have next_crawl_at NULL, which
                            # never satisfies "<= now", so they're excluded.)
                            sa.and_(
                                Page.status.in_(
                                    [STATUS_DISCOVERED, STATUS_CRAWLED, STATUS_DEAD]
                                ),
                                Page.next_crawl_at <= now,
                            ),
                            sa.and_(
                                Page.status == STATUS_IN_PROGRESS,
                                Page.claimed_at < stale_before,
                            ),
                        )
                    )
                    .order_by(Page.score.desc(), Page.depth.asc(), Page.created_at.asc())
                    .limit(1)
                )
                stmt = stmt.where(Page.depth <= self.settings.max_depth)
                if self.settings.allowed_hosts:
                    stmt = stmt.where(Page.hostname.in_(self.settings.allowed_hosts))
                page = (await session.execute(stmt)).scalar_one_or_none()
                if page is None:
                    return None
                page.status = STATUS_IN_PROGRESS
                page.claimed_at = now
                page.claim_seq = (page.claim_seq or 0) + 1
                await session.commit()
                return CrawlItem(
                    url=page.url, depth=page.depth, parent=page.parent_url,
                    score=page.score, claim_token=page.claim_seq,
                    targeted=bool(page.targeted),
                )

    async def complete(
        self,
        page: Page,
        records: list,
        embedding: tuple[str, int, bytes] | None = None,
        claim_token: int | None = None,
    ) -> bool | None:
        """Persist the outcome of processing ``page`` and schedule its next crawl.

        Returns True if the page's content changed since the last crawl.
        ``claim_token`` is the ``claim_token`` from the CrawlItem; if the DB row's
        ``claim_seq`` no longer matches (another worker reclaimed a stale
        in-progress row), this completion is discarded to avoid a double write.
        """
        now = utcnow()
        base = self.settings.recrawl_interval_s
        async with self.db.write_session() as session:
            row = (
                await session.execute(sa.select(Page).where(Page.url == page.url))
            ).scalar_one_or_none()
            existed = row is not None
            if not existed:  # shouldn't happen (claim created it), but be safe
                row = Page(url=page.url, created_at=now)
                session.add(row)

            if existed and claim_token is not None and (
                row.claim_seq != claim_token or row.status != STATUS_IN_PROGRESS
            ):
                log.debug("discarding stale completion for %s", page.url)
                return None

            # --- transient/permanent fetch failure: never destroy good content --
            if page.status == STATUS_DEAD:
                fails = (row.consecutive_failures or 0) + 1
                was_reachable = bool(row.content_sha256)
                row.consecutive_failures = fails
                row.attempts = (row.attempts or 0) + 1
                row.error = page.error
                row.http_status = page.http_status
                row.fetched_at = page.fetched_at
                # Only the transition is news. Re-reporting it on every retry —
                # including manual ones, which reset the failure counter — would
                # bury the outage under its own follow-ups.
                if was_reachable and not await timeline.is_offline(session, row.url):
                    timeline.record(
                        session,
                        timeline.PAGE_UNREACHABLE,
                        page_url=row.url,
                        hostname=row.hostname,
                        summary=f"Stopped responding: {row.title or row.url}",
                        detail=page.error,
                    )
                if base <= 0 or fails >= self.settings.max_fetch_failures:
                    if row.status != STATUS_DEAD or was_reachable:
                        timeline.record(
                            session,
                            timeline.PAGE_DEAD,
                            page_url=row.url,
                            hostname=row.hostname,
                            summary=f"Given up after {fails} failed fetch(es): {row.url}",
                            detail=page.error,
                        )
                    row.status = STATUS_DEAD
                    row.next_crawl_at = None  # give up permanently
                else:
                    backoff = min(base * fails, self.settings.recrawl_interval_max_s)
                    row.next_crawl_at = now + dt.timedelta(seconds=backoff)
                    # A previously-crawled page keeps its content and stays "crawled"
                    # (its intel is still valid). A never-crawled page reads as
                    # "dead" but is still retried when due (claim() allows that).
                    row.status = STATUS_CRAWLED if row.content_sha256 else STATUS_DEAD
                await session.commit()
                return False

            # --- successful fetch (crawled or blocked) ---------------------------
            changed = (row.content_sha256 != page.content_sha256
                       or bool(row.blocked) != bool(page.blocked))
            first_fetch = row.content_sha256 is None

            # A page answering again after an outage is a service coming back:
            # takedown lifted, infrastructure rotated, or an outage over.
            if not first_fetch and await timeline.is_offline(session, row.url):
                timeline.record(
                    session,
                    timeline.PAGE_RECOVERED,
                    page_url=row.url,
                    hostname=row.hostname,
                    summary=f"Back online: {row.title or row.url}",
                )

            if changed:
                if row.content_sha256 and not row.blocked:
                    has_version = await session.scalar(sa.select(PageVersion.id).where(
                        PageVersion.page_url == row.url
                    ).limit(1))
                    if has_version is None:
                        session.add(snapshot(row, legacy=True))
                if first_fetch:
                    timeline.record(
                        session,
                        timeline.PAGE_NEW,
                        page_url=page.url,
                        hostname=page.hostname,
                        summary=f"New page: {page.title or page.url}",
                    )
                else:
                    timeline.record(
                        session,
                        timeline.PAGE_CHANGED,
                        page_url=row.url,
                        hostname=row.hostname,
                        summary=f"Content changed: {page.title or row.title or row.url}",
                    )
                await self._record_new_identifiers(session, row, records, first_fetch)

                for field in _RESULT_FIELDS:
                    setattr(row, field, getattr(page, field))
                row.content_changed_at = now
                # Derived records reflect the CURRENT page version — replace,
                # don't accumulate duplicates/stale data across recrawls.
                for table in _DERIVED_TABLES:
                    await session.execute(sa.delete(table).where(table.page_url == page.url))
                for rec in records:
                    session.add(rec)
                if embedding is not None:
                    await self._upsert_embedding(session, page.url, embedding)
                else:
                    await session.execute(sa.delete(Embedding).where(
                        Embedding.page_url == page.url
                    ))
            else:
                # Recrawl with identical content: light-touch; keep content/iocs/embedding.
                row.status = page.status
                row.http_status = page.http_status
                row.fetched_at = page.fetched_at
                row.error = None
                row.raw_body = page.raw_body
                row.body_truncated = page.body_truncated
                row.final_url = page.final_url
                row.capture_metadata = page.capture_metadata

            row.content_captured_at = page.fetched_at
            row.processing_failures = 0

            if page.blocked:
                row.raw_body = row.content = row.html = None
                await session.execute(sa.delete(PageVersion).where(
                    PageVersion.page_url == page.url
                ))
            elif page.status == STATUS_CRAWLED:
                if changed or not await session.scalar(sa.select(PageVersion.id).where(
                    PageVersion.page_url == page.url
                ).limit(1)):
                    await retain_version(session, page, self.settings.versions_per_page)

            row.consecutive_failures = 0
            row.attempts = (row.attempts or 0) + 1

            if base > 0 and page.status == STATUS_CRAWLED:
                if changed or not row.recrawl_interval_s:
                    interval = base
                else:
                    interval = min(row.recrawl_interval_s * 2, self.settings.recrawl_interval_max_s)
                row.recrawl_interval_s = interval
                row.next_crawl_at = now + dt.timedelta(seconds=interval)
            else:
                row.next_crawl_at = None  # blocked/media: don't reschedule

            await session.commit()
        return changed

    async def heartbeat(self, item: CrawlItem) -> bool:
        async with self.db.write_session() as session:
            result = await session.execute(sa.update(Page).where(
                Page.url == item.url, Page.claim_seq == item.claim_token,
                Page.status == STATUS_IN_PROGRESS,
            ).values(claimed_at=utcnow()))
            await session.commit()
            return result.rowcount == 1

    async def release(self, item: CrawlItem, error: str | None = None) -> None:
        """Cancellation/processing errors are not observations of a host outage."""
        async with self.db.write_session() as session:
            row = (await session.execute(sa.select(Page).where(
                Page.url == item.url, Page.claim_seq == item.claim_token,
                Page.status == STATUS_IN_PROGRESS,
            ))).scalar_one_or_none()
            if row is None:
                return
            if error:
                row.processing_failures = (row.processing_failures or 0) + 1
                row.attempts = (row.attempts or 0) + 1
            row.status = STATUS_CRAWLED if row.content_sha256 else STATUS_DISCOVERED
            row.error, row.claimed_at = error, None
            row.next_crawl_at = utcnow() + dt.timedelta(seconds=60)
            if (row.processing_failures or 0) >= self.settings.max_fetch_failures:
                row.status, row.next_crawl_at = "error", None
            await session.commit()

    @staticmethod
    async def _record_new_identifiers(session, row, records: list, first_fetch: bool) -> None:
        """Emit an event when an actor identifier appears that wasn't there before.

        This is the vendor-rotation signal: a PGP fingerprint changing on a
        listing page means the operator re-keyed, was compromised, or is being
        impersonated — and it is invisible in the stored data, because the
        derived records for a changed page are deleted and rebuilt from scratch a
        few lines below. Compared before that happens.

        Restricted to STRONG_TYPES: onion links and victim emails churn constantly
        and would drown the signal. Nothing is emitted on a page's first fetch —
        everything is "new" then, which is not news.
        """
        if first_fetch:
            return
        fresh = {
            (r.ioc_type, r.value)
            for r in records
            if isinstance(r, Ioc) and r.ioc_type in STRONG_TYPES
        }
        if not fresh:
            return
        known = set(
            (
                await session.execute(
                    sa.select(Ioc.ioc_type, Ioc.value).where(Ioc.page_url == row.url)
                )
            ).all()
        )
        for ioc_type, value in sorted(fresh - known):
            timeline.record(
                session,
                timeline.INDICATOR_NEW,
                page_url=row.url,
                hostname=row.hostname,
                summary=f"New {ioc_type} on {row.title or row.url}",
                detail=value,
            )

    @staticmethod
    async def _upsert_embedding(session, url: str, embedding: tuple[str, int, bytes]) -> None:
        model, dim, vec = embedding
        emb = (
            await session.execute(sa.select(Embedding).where(Embedding.page_url == url))
        ).scalar_one_or_none()
        if emb is None:
            session.add(Embedding(page_url=url, model=model, dim=dim, vector=vec))
        else:
            emb.model, emb.dim, emb.vector = model, dim, vec

    async def counts(self) -> dict:
        async with self.db.session() as session:
            rows = (
                await session.execute(
                    sa.select(Page.status, sa.func.count()).group_by(Page.status)
                )
            ).all()
        return {status: n for status, n in rows}
