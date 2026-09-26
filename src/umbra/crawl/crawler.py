"""Crawl orchestrator.

Spawns N async workers that pull from a shared DB-backed :class:`Scheduler`. Each
worker loops: claim -> fetch -> compliance gate -> parse -> persist -> enrich ->
embed -> discover children. Because the frontier lives in the database, the whole
crawl is resumable: re-running continues where it stopped and picks up any pages
now due for recrawl.

Termination is race-free: a worker exits only when the scheduler has nothing to
hand out *and* no worker is mid-request (``_in_flight == 0``), or when a global
limit (pages/depth) is reached. All shared counters are safe without locks — one
event loop, cooperative scheduling.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING

from ..compliance.policy import CompliancePolicy, sha256_bytes
from ..config import Settings
from ..db import Database
from ..fetch.client import TorFetcher
from ..intel.embeddings import Embedder, to_bytes
from ..logging import get_logger
from ..models import STATUS_BLOCKED, STATUS_CRAWLED, STATUS_DEAD, Ioc, Page
from ..scope import ScopeError, allows, canonical_hosts, valid_host
from .parse import hostname, is_onion, parse_page
from .scheduler import CrawlItem, Scheduler
from .scorer import Scorer, prioritise

if TYPE_CHECKING:  # ``enrich.base`` imports from this package — importing it at
    # runtime makes ``import umbra.enrich.ioc`` (before anything else) fail with a
    # circular-import error. It is only ever needed as an annotation here.
    from ..enrich.base import Enricher

log = get_logger("crawler")


class Crawler:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        fetcher: TorFetcher,
        scorer: Scorer,
        policy: CompliancePolicy,
        enrichers: list[Enricher] | None = None,
        embedder: Embedder | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.fetcher = fetcher
        self.scorer = scorer
        self.policy = policy
        self.enrichers = enrichers or []
        self.embedder = embedder
        self.scheduler = Scheduler(db, settings)

        self.pages_crawled = 0
        self.pages_blocked = 0
        self.pages_dead = 0
        self.pages_changed = 0
        self.iocs_found = 0
        self._in_flight = 0
        self._stop_requested = False
        self.processing_errors = 0
        self._compute_lock = asyncio.Lock()
        self._dispatch_lock = asyncio.Lock()

    def request_stop(self) -> None:
        """Ask the crawl to wind down. Workers finish the page they're on and
        exit cleanly, so nothing is left half-written."""
        self._stop_requested = True
        log.info("stop requested — workers will finish their current page and exit")

    # -- public API -------------------------------------------------------

    def _reset_run_state(self) -> None:
        """Clear per-run state so a Crawler can be reused for another pass.

        ``max_pages`` is a budget *per crawl*, but the counters live on the
        instance and the long-running worker reuses one Crawler for every pass.
        Without this reset the budget becomes a lifetime cap: the first pass
        reaches it, and every later pass sees ``pages_crawled >= max_pages`` and
        exits before fetching anything — permanently, and silently, because the
        cumulative counters keep reporting the first pass's totals and the log
        line still reads like healthy activity.

        ``_stop_requested`` is cleared for the same reason: a stop from the GUI
        must end the current crawl, not disable the crawler for good.
        """
        self.pages_crawled = 0
        self.pages_blocked = 0
        self.pages_dead = 0
        self.pages_changed = 0
        self.iocs_found = 0
        self._stop_requested = False
        self.processing_errors = 0

    async def run(
        self, seeds: list[str], force_seeds: bool = False, pin_seeds: bool = False
    ) -> dict:
        """``force_seeds`` = an explicit user request (GUI/CLI): re-crawl the given
        seeds now even if they were crawled or failed recently. The background
        worker leaves it False so its seed list respects the recrawl schedule.
        ``pin_seeds`` keeps the crawl on the seeds' own hosts (see Scheduler.seed).
        """
        self._reset_run_state()
        self.settings.allowed_hosts = canonical_hosts(self.settings.allowed_hosts)
        if self.settings.strict_scope and not self.settings.allowed_hosts:
            self.settings.allowed_hosts = sorted({valid_host(url) for url in seeds})
            if not self.settings.allowed_hosts:
                raise ScopeError("Strict scope needs seed URLs or allowed hosts")
        for url in seeds:
            if not allows(url, self.settings.allowed_hosts):
                raise ScopeError("Seed outside allowed hosts")
        if hasattr(self.fetcher, "allowed_hosts"):
            self.fetcher.allowed_hosts = self.settings.allowed_hosts
        await self.scheduler.load()  # resume: rehydrate frontier state from the DB
        added = await self.scheduler.seed(seeds, force=force_seeds, pin=pin_seeds)
        log.info(
            "starting crawl: %d seed(s) queued, %d worker(s)", added, self.settings.max_workers
        )
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.settings.max_workers)]
        try:
            await asyncio.gather(*workers)
        finally:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        return await self.stats()

    async def stats(self) -> dict:
        return {
            "stop_reason": ("paused" if self._stop_requested else
                            "page_budget_reached" if self.settings.max_pages > 0 and
                            self.pages_crawled >= self.settings.max_pages else
                            "no_eligible_pages_in_scope"),
            "crawled": self.pages_crawled,
            "changed": self.pages_changed,
            "blocked": self.pages_blocked,
            "dead": self.pages_dead,
            "iocs": self.iocs_found,
            "processing_errors": self.processing_errors,
            "db_status": await self.scheduler.counts(),
        }

    def _should_stop(self) -> bool:
        if self._stop_requested:
            return True
        return self.settings.max_pages > 0 and self.pages_crawled >= self.settings.max_pages

    # -- worker loop ------------------------------------------------------

    async def _worker(self, wid: int) -> None:
        while True:
            async with self._dispatch_lock:
                if self._should_stop():
                    return
                # Reserve one possible successful completion per in-flight page.
                # This makes the success budget exact even with many workers.
                if (self.settings.max_pages > 0 and
                        self.pages_crawled + self._in_flight >= self.settings.max_pages):
                    item = None
                else:
                    item = await self.scheduler.claim()
                    if item is not None:
                        self._in_flight += 1
            if item is None:
                # Nothing to claim: if nobody is working either, the crawl is done.
                if self._in_flight == 0:
                    return
                await asyncio.sleep(0.05)
                continue

            heartbeat = asyncio.create_task(self._heartbeat(item))
            try:
                await self._process(item)
            except asyncio.CancelledError:
                await self.scheduler.release(item)
                raise
            except ScopeError as exc:
                await self.scheduler.release(item, f"Scope blocked: {exc}")
                self.processing_errors += 1
            except Exception as exc:
                log.exception("worker %d failed on %s", wid, item.url)
                # Record it as a failed attempt. Logging alone left the page
                # "in_progress" with zero attempts: the stale-claim reclaim handed
                # it out again five minutes later, it failed the same way, and so
                # on forever — a traceback every reclaim and a page that could
                # never become dead or crawled. Completing it as a failure puts it
                # on the same backoff / max-failures path as an unreachable host.
                try:
                    await self.scheduler.release(item, f"{type(exc).__name__}: {exc}"[:512])
                    self.processing_errors += 1
                except Exception:
                    log.exception("could not record the failure for %s", item.url)
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat
                self._in_flight -= 1

    async def _heartbeat(self, item: CrawlItem) -> None:
        while True:
            await asyncio.sleep(max(0.1, self.settings.reclaim_after_s / 3))
            if not await self.scheduler.heartbeat(item):
                return

    async def _compute(self, function, *args):
        # A bounded executor path keeps model inference off the network event loop
        # and avoids concurrently entering an embedder that may not be thread-safe.
        async with self._compute_lock:
            return await asyncio.to_thread(function, *args)

    # -- per-page pipeline ------------------------------------------------

    async def _process(self, item: CrawlItem) -> None:
        result = await self.fetcher.fetch(item.url)

        # blocked/stored_content are NOT NULL; set them here because column
        # defaults only apply when *this* object is flushed, and the scheduler
        # copies these attributes onto the persisted row instead.
        page = Page(
            url=item.url,
            parent_url=item.parent,
            hostname=hostname(item.url),
            depth=item.depth,
            score=item.score,
            http_status=result.status,
            fetched_at=result.fetched_at,
            blocked=False,
            stored_content=False,
        )

        if not result.ok or not result.body:
            page.status = STATUS_DEAD
            page.error = result.error
            accepted = await self.scheduler.complete(page, [], claim_token=item.claim_token)
            self.pages_dead += int(accepted is not None)
            return

        page.content_sha256 = sha256_bytes(result.body)
        page.content_length = len(result.body)

        decision = self.policy.evaluate(
            item.url, result.text, result.content_type, content_sha256=page.content_sha256
        )
        if decision.blocked:
            page.status = STATUS_BLOCKED
            page.blocked = True
            page.block_reason = ",".join(decision.categories) or decision.reason
            # body deliberately not stored
            accepted = await self.scheduler.complete(page, [], claim_token=item.claim_token)
            self.pages_blocked += int(accepted is not None)
            log.info("blocked %s (%s)", item.url, page.block_reason)
            return

        page.body_truncated = result.truncated
        page.final_url = result.final_url or item.url
        parsed = await self._compute(parse_page, result.text or "", page.final_url)
        page.status = STATUS_CRAWLED
        page.title = parsed.title
        page.description = parsed.description
        page.keywords = parsed.keywords
        if decision.store_content:
            if self.policy.store_text:
                page.content = parsed.text
                page.stored_content = True
            if self.policy.store_html:
                page.html = result.text
                page.raw_body = result.body

        # Skip the expensive enrich/embed work when a recrawl returns identical
        # content — the existing IOCs/embedding are still valid and re-running the
        # LLM would just burn tokens. (complete() leaves them untouched when
        # unchanged.)
        prior_sha = await self.scheduler.prior_content_sha(item.url)
        unchanged = prior_sha is not None and prior_sha == page.content_sha256

        records: list = []
        embedding = None
        from .. import __version__
        page.capture_metadata = json.dumps({
            "collector_version": __version__,
            "settings": {k: getattr(self.settings, k) for k in (
                "use_tor", "max_depth", "max_response_bytes", "store_text", "store_html",
                "strict_scope", "allowed_hosts", "llm_enabled", "embedder_kind")},
            "extractors": [getattr(e, "name", type(e).__name__) for e in self.enrichers],
            "limitations": ["No trusted timestamp", "Site claims are not independently verified"],
        })
        extraction_errors = []
        if not unchanged:
            for enricher in self.enrichers:
                try:
                    records.extend(await enricher.enrich(page, parsed))
                except Exception as exc:
                    extraction_errors.append({"extractor": getattr(enricher, "name", "?"),
                                              "error_type": type(exc).__name__})
                    log.exception(
                        "enricher %s failed on %s", getattr(enricher, "name", "?"), item.url
                    )
            if self.embedder is not None and parsed.text:
                vec = await self._compute(self.embedder.embed, parsed.text)
                embedding = (self.embedder.name, self.embedder.dim, to_bytes(vec))

        page.extraction_errors = json.dumps(extraction_errors)
        n_iocs = sum(1 for r in records if isinstance(r, Ioc))
        changed = await self.scheduler.complete(
            page, records, embedding, claim_token=item.claim_token
        )
        if changed is None:
            return
        self.pages_crawled += 1
        self.pages_changed += int(changed)
        self.iocs_found += n_iocs
        log.info(
            "crawled [%d] %s (%d links, %d records%s)",
            item.depth, item.url, len(parsed.links), len(records),
            "" if changed else ", unchanged",
        )

        if self.settings.per_request_delay:
            await asyncio.sleep(self.settings.per_request_delay)

        # Discover children.
        if item.depth < self.settings.max_depth:
            children = []
            for link in parsed.links:
                if not allows(link.url, self.settings.allowed_hosts):
                    continue
                if not self.settings.allow_clearnet and not is_onion(link.url):
                    continue
                def score_link(link=link):
                    return prioritise(
                        self.scorer, link, item.depth, targeted=item.targeted,
                        pinned_hosts=self.scheduler.pinned_hosts,
                        off_host_factor=self.settings.off_host_priority,
                    )
                score = await self._compute(score_link)
                if score < self.settings.focus_threshold:
                    continue
                children.append(
                    CrawlItem(
                        url=link.url, depth=item.depth + 1, parent=item.url,
                        score=score, targeted=item.targeted,
                    )
                )
            await self.scheduler.add_many(children)
