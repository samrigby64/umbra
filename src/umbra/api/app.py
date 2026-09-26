"""FastAPI query + management service — the sellable product surface.

Exposes the crawled intelligence: semantic search, pages, IOCs, resolved actors,
leaked-credential lookup, marketplace listings, and watchlist/alert management.

Auth: send ``X-API-Key``. As a convenience, while **no** active API keys exist
the service runs open (local dev); once you create one, a valid key is required.
Build via ``create_app(settings)``; run with ``umbra serve``.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse

from ..alerting import KINDS, evaluate_watchlists, parse_event_value
from .. import __version__
from ..config import Settings
from ..db import Database
from ..evidence import build_bundle as build_evidence_bundle
from ..factory import build_crawler, build_enrichers, build_scorer
from ..intel.embeddings import build_embedder, search, exact_search
from ..scope import ScopeError, allows, canonical_hosts, valid_host
from .investigations import register as register_investigations
from ..intel.entities import STRONG_TYPES, resolve_actors
from ..logging import get_logger
from ..netguard import UnsafeDestination, check_url
from ..reprocess import embedding_coverage, reembed_pages, reprocess_pages, rescore_frontier
from ..runs import health as collection_health
from ..runs import list_runs, record_run
from ..sources import available as available_packs
from ..sources import seed_pack
from ..stix import build_bundle as build_stix_bundle
from ..timeline import ALL_KINDS as ALL_EVENT_KINDS
from ..timeline import backfill as backfill_timeline
from ..timeline import host_liveness, list_events, not_answering
from ..models import (
    Actor,
    ActorIdentifier,
    ApiKey,
    Alert,
    Credential,
    Ioc,
    Listing,
    Page,
    Watchlist,
)

log = get_logger("api")
_UI_FILE = Path(__file__).parent / "static" / "index.html"
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _filter_ioc_type(stmt, type: str | None):
    """Apply the ``?type=`` filter: one type, a comma-separated set, or ``actor``.

    Onion addresses outnumber every other indicator by roughly a hundred to one —
    they are the link graph, not intelligence — so browsing raw indicators buries
    the handful of wallets and keys that actually matter. ``type=actor`` resolves
    to :data:`STRONG_TYPES`, the exact set entity resolution links on, so the
    filter cannot drift away from what the actor graph considers an identifier.
    """
    if not type:
        return stmt
    if type == "actor":
        return stmt.where(Ioc.ioc_type.in_(STRONG_TYPES))
    wanted = [t.strip() for t in type.split(",") if t.strip()]
    if len(wanted) == 1:
        return stmt.where(Ioc.ioc_type == wanted[0])
    return stmt.where(Ioc.ioc_type.in_(wanted))


async def _ensure_bootstrap_key(db: Database) -> None:
    """Never run open on a network-reachable bind.

    "Open until the first key exists" is a fine convenience on loopback and a
    serious hazard anywhere else: the shipped compose file binds ``0.0.0.0``, and
    an operator who skips the create-a-key step has an unauthenticated admin
    API on the network — one that can point the crawler at arbitrary URLs and
    deliver collected intelligence to arbitrary webhooks. The first-run
    experience of most server software applies here: mint an admin key, show it
    once, and make the operator replace it.
    """
    async with db.session() as s:
        exists = (
            await s.execute(sa.select(ApiKey.id).where(ApiKey.active.is_(True)).limit(1))
        ).first()
        if exists:
            return
        key = secrets.token_hex(24)
        s.add(ApiKey(key=key, name="bootstrap-admin", role="admin"))
        await s.commit()
    banner = "=" * 72
    log.warning(
        "\n%s\nNo API key existed and the service is bound to a non-loopback address,\n"
        "so it will NOT run open. A bootstrap admin key has been created:\n\n"
        "    X-API-Key: %s\n\n"
        "This is shown once. Create your own with `umbra apikey --role admin`.\n%s",
        banner, key, banner,
    )


def create_app(settings: Settings | None = None, *, public: bool = False) -> FastAPI:
    """Build the service. ``public`` means the caller intends to bind to a
    non-loopback address; the app then refuses to start without an API key."""
    settings = settings or Settings()
    db = Database(settings.database_url)
    db.require_individual_accounts = settings.beta_mode
    embedder = build_embedder(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        from ..maintenance import backup, database_path
        from ..backup_crypto import key_path
        from contextlib import suppress
        async def backup_once():
            try:
                path = database_path(settings.database_url)
            except ValueError:
                return  # PostgreSQL has its own backup tools.
            if path.exists() and path.stat().st_size:
                await asyncio.to_thread(backup, settings.database_url,
                                        key_file=key_path(settings))
        if settings.backup_interval_hours > 0:
            await backup_once()  # Abort startup if a required SQLite backup fails.
        await db.create_all()
        async def backup_loop():
            while True:
                await asyncio.sleep(settings.backup_interval_hours * 3600)
                try:
                    await backup_once()
                except Exception:
                    log.exception("Automatic backup failed")
        backup_task = asyncio.create_task(backup_loop()) if settings.backup_interval_hours > 0 else None
        if public and not settings.beta_mode:
            await _ensure_bootstrap_key(db)
        from ..jobs import loop as job_loop
        jobs_task = asyncio.create_task(job_loop(db, settings)) if not settings.preview_mode else None
        try:
            yield
        finally:
            if jobs_task:
                jobs_task.cancel()
                with suppress(asyncio.CancelledError):
                    await jobs_task
            if backup_task:
                backup_task.cancel()
                with suppress(asyncio.CancelledError):
                    await backup_task
            await db.dispose()

    app = FastAPI(title="Umbra Intelligence API", version=__version__, lifespan=lifespan)

    async def current_role(x_api_key: str | None = Header(default=None)) -> str:
        """Resolve the caller's role. While no keys exist the service runs open
        ('open' acts as admin for local dev); once a key exists, a valid key is
        required and its role ('viewer' | 'admin') is enforced.
        """
        from ..access import principal
        return (await principal(db, x_api_key))["role"]

    async def require_admin(role: str = Depends(current_role)) -> None:
        if role not in ("open", "admin"):
            raise HTTPException(status_code=403, detail="admin role required")

    auth = [Depends(current_role)]       # any valid key (read)
    admin = [Depends(require_admin)]     # admin only (management)
    register_investigations(app, db, settings, auth, admin)
    from .workspace import register as register_workspace
    register_workspace(app, db, settings, auth, admin)
    from .collection import register as register_collection
    from .account_security import register as register_security
    register_collection(app, db, settings, auth, admin)
    register_security(app, db, settings, auth, admin)
    @app.get("/workflow.js", include_in_schema=False)
    async def workflow_script():
        return FileResponse(_UI_FILE.parent / "workflow.js",
                            headers={"Cache-Control": "no-cache"})

    @app.middleware("http")
    async def _audit(request, call_next):
        origin = request.headers.get('origin')
        if request.method not in ('GET', 'HEAD', 'OPTIONS') and origin:
            from urllib.parse import urlsplit
            if urlsplit(origin).netloc != request.headers.get('host'):
                return Response('Cross-origin mutation refused', status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        key = request.headers.get("x-api-key")
        log.info(
            "api %s %s key=%s -> %s",
            request.method, request.url.path,
            "present" if key else "-", response.status_code,
        )
        return response

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": __version__, "preview": settings.preview_mode}

    @app.get("/stats", dependencies=auth)
    async def stats() -> dict:
        async with db.session() as s:
            async def count(model) -> int:
                return (await s.execute(sa.select(sa.func.count()).select_from(model))).scalar()

            by_status = (
                await s.execute(sa.select(Page.status, sa.func.count()).group_by(Page.status))
            ).all()
            return {
                "pages_by_status": {k: v for k, v in by_status},
                "iocs": await count(Ioc),
                "actors": await count(Actor),
                "credentials": await count(Credential),
                "listings": await count(Listing),
                "watchlists": await count(Watchlist),
                "alerts": await count(Alert),
            }

    @app.get("/overview", dependencies=auth)
    async def overview() -> dict:
        """Everything the dashboard needs in one call: counts, breakdowns, and
        recent activity (with watchlist names resolved, not raw IDs)."""
        async with db.session() as s:
            async def count(model) -> int:
                return (await s.execute(sa.select(sa.func.count()).select_from(model))).scalar()

            async def grouped(col, limit=None):
                stmt = (
                    sa.select(col, sa.func.count())
                    .where(col.isnot(None))
                    .group_by(col)
                    .order_by(sa.func.count().desc())
                )
                if limit:
                    stmt = stmt.limit(limit)
                return [{"name": k, "count": v} for k, v in (await s.execute(stmt)).all()]

            by_status = dict(
                (await s.execute(sa.select(Page.status, sa.func.count()).group_by(Page.status))).all()
            )
            counts = {
                # "pages" means pages actually FETCHED — not every URL we know
                # about. Queued links are counted separately so the dashboard
                # can't imply we've collected more than we have.
                "pages": await s.scalar(sa.select(sa.func.count()).select_from(Page).where(
                    Page.content.is_not(None), Page.blocked.is_(False))),
                "queued": by_status.get("discovered", 0),
                "unreachable": await s.scalar(
                    sa.select(sa.func.count()).select_from(Page).where(not_answering())
                ),
                "iocs": await count(Ioc),
                "unique_iocs": await s.scalar(sa.select(sa.func.count()).select_from(sa.select(Ioc.ioc_type, Ioc.value).distinct().subquery())),
                "actors": await count(Actor),
                "credentials": await count(Credential),
                "listings": await count(Listing),
                "watchlists": await count(Watchlist),
                "alerts": await count(Alert),
            }
            recent_pages = (
                await s.execute(
                    sa.select(Page).options(sa.orm.defer(Page.raw_body))
                    .where(Page.status == "crawled")
                    .order_by(Page.fetched_at.desc())
                    .limit(8)
                )
            ).scalars().all()
            recent_alerts = (
                await s.execute(
                    sa.select(Alert, Watchlist)
                    .join(Watchlist, Alert.watchlist_id == Watchlist.id)
                    .order_by(Alert.created_at.desc())
                    .limit(8)
                )
            ).all()
            return {
                "counts": counts,
                # On the dashboard because the counts above cannot show it: they
                # look identical whether collection is running or died an hour ago.
                "collection": await collection_health(db, settings.health_stale_after_s),
                "pages_by_status": by_status,
                "pages_by_type": await grouped(Page.page_type),
                "pages_by_threat": await grouped(Page.threat_category),
                "top_hosts": await grouped(Page.hostname, limit=8),
                "top_ioc_types": await grouped(Ioc.ioc_type, limit=8),
                "recent_pages": [_page_summary(p) for p in recent_pages],
                "recent_alerts": [
                    {
                        "watchlist": w.name, "kind": w.kind, "page_url": a.page_url,
                        "matched_value": a.matched_value, "delivered": a.delivered,
                    }
                    for a, w in recent_alerts
                ],
            }

    @app.get("/search", dependencies=auth)
    async def semantic_search(q: str, k: int = Query(10, ge=1, le=100),
                              mode: str = "semantic") -> dict:
        if mode not in ("semantic", "exact"):
            raise HTTPException(400, "mode must be semantic or exact")
        results = await (exact_search(db, q, k) if mode == "exact"
                         else search(db, embedder, q, top_k=k))
        payload = {"query": q, "results": results}
        if not results and mode == "semantic":
            # Empty results have two very different causes: nothing matched, or
            # the corpus is embedded under a different model and is therefore
            # invisible to this query. Say which, rather than letting a config
            # mismatch masquerade as a genuine miss.
            coverage = await embedding_coverage(db, embedder)
            if coverage["searchable_now"] == 0 and coverage["stale"] > 0:
                payload["warning"] = (
                    f"{coverage['stale']} page(s) are embedded with a different model "
                    f"than the active one ({coverage['embedder']}, dim {coverage['dim']}) "
                    "and cannot be searched. Run Re-embed to rebuild them."
                )
            payload["coverage"] = coverage
        return payload

    @app.get("/timeline", dependencies=auth)
    async def get_timeline(
        kind: str | None = None,
        host: str | None = None,
        notable: bool = False,
        limit: int = Query(100, le=500),
    ) -> dict:
        """What changed, most recent first. ``notable=true`` drops routine churn."""
        return {
            "events": await list_events(
                db, kind=kind, host=host, notable_only=notable, limit=limit
            )
        }

    @app.get("/runs", dependencies=auth)
    async def get_runs(limit: int = Query(20, le=200)) -> dict:
        """Collection health plus the recent pass log."""
        return {
            "health": await collection_health(db, settings.health_stale_after_s),
            "runs": await list_runs(db, limit=limit),
        }

    @app.get("/liveness", dependencies=auth)
    async def get_liveness(limit: int = Query(200, le=500)) -> dict:
        """Per-service up/down state, offline services first."""
        return {"hosts": await host_liveness(db, limit=limit)}

    @app.get("/embeddings/coverage", dependencies=auth)
    async def embeddings_coverage() -> dict:
        """How much of the corpus the *current* embedder can actually search."""
        return await embedding_coverage(db, embedder)

    @app.get("/pages", dependencies=auth)
    async def list_pages(
        host: str | None = None,
        page_type: str | None = None,
        threat: str | None = None,
        status: str | None = None,
        limit: int = Query(20, le=200),
        offset: int = 0,
    ) -> dict:
        stmt = sa.select(Page).options(sa.orm.defer(Page.raw_body))
        if host:
            stmt = stmt.where(Page.hostname == host)
        if page_type:
            stmt = stmt.where(Page.page_type == page_type)
        if threat:
            stmt = stmt.where(Page.threat_category == threat)
        if status:
            stmt = stmt.where(Page.status == status)
        async with db.session() as s:
            rows = (await s.execute(stmt.limit(limit).offset(offset))).scalars().all()
        return {"pages": [_page_summary(p) for p in rows]}

    @app.get("/page", dependencies=auth)
    async def get_page(url: str) -> dict:
        async with db.session() as s:
            page = (await s.execute(sa.select(Page).options(sa.orm.defer(Page.raw_body)).where(Page.url == url))).scalar_one_or_none()
            if page is None:
                raise HTTPException(status_code=404, detail="page not found")
            iocs = (
                await s.execute(sa.select(Ioc).where(Ioc.page_url == url))
            ).scalars().all()
        return {
            **_page_summary(page),
            "content": page.content,
            "iocs": [{"type": i.ioc_type, "value": i.value, "context": i.context} for i in iocs],
        }

    @app.get("/iocs", dependencies=auth)
    async def list_iocs(
        type: str | None = None,
        value: str | None = None,
        distinct: bool = False,
        limit: int = Query(50, le=500),
    ) -> dict:
        """``distinct=true`` collapses repeat sightings: one row per (type, value)
        with how many pages it was seen on, most-seen first. Without it, a row
        cap fills with the same three wallets repeated per page and everything
        rarer — PGP keys, say — silently falls off the end. Observed exactly so."""
        if distinct:
            stmt = _filter_ioc_type(
                sa.select(
                    Ioc.ioc_type, Ioc.value,
                    sa.func.count().label("pages"), sa.func.min(Ioc.page_url).label("page_url"),
                ),
                type,
            )
            if value:
                stmt = stmt.where(Ioc.value == value)
            stmt = stmt.group_by(Ioc.ioc_type, Ioc.value).order_by(sa.desc("pages"))
            async with db.session() as s:
                rows = (await s.execute(stmt.limit(limit))).all()
            return {"iocs": [
                {"type": t, "value": v, "pages": n, "page_url": u} for t, v, n, u in rows
            ]}
        stmt = _filter_ioc_type(sa.select(Ioc), type)
        if value:
            stmt = stmt.where(Ioc.value == value)
        async with db.session() as s:
            rows = (await s.execute(stmt.limit(limit))).scalars().all()
        return {"iocs": [{"type": i.ioc_type, "value": i.value, "page_url": i.page_url} for i in rows]}

    @app.get("/actors", dependencies=auth)
    async def list_actors(limit: int = Query(50, le=500)) -> dict:
        async with db.session() as s:
            rows = (
                await s.execute(
                    sa.select(Actor).order_by(Actor.page_count.desc()).limit(limit)
                )
            ).scalars().all()
        return {"actors": [{"id": a.id, "label": a.label, "page_count": a.page_count} for a in rows]}

    @app.get("/actor/{actor_id}", dependencies=auth)
    async def get_actor(actor_id: int) -> dict:
        async with db.session() as s:
            actor = (
                await s.execute(sa.select(Actor).where(Actor.id == actor_id))
            ).scalar_one_or_none()
            if actor is None:
                raise HTTPException(status_code=404, detail="actor not found")
            idents = (
                await s.execute(
                    sa.select(ActorIdentifier).where(ActorIdentifier.actor_id == actor_id)
                )
            ).scalars().all()
        return {
            "id": actor.id,
            "label": actor.label,
            "page_count": actor.page_count,
            "identifiers": [{"type": i.ioc_type, "value": i.value} for i in idents],
        }

    @app.get("/credentials", dependencies=auth)
    async def lookup_credentials(
        email: str | None = None, domain: str | None = None, limit: int = Query(50, le=500)
    ) -> dict:
        if not email and not domain:
            raise HTTPException(status_code=400, detail="provide email or domain")
        stmt = sa.select(Credential)
        if email:
            stmt = stmt.where(Credential.email == email.lower())
        if domain:
            stmt = stmt.where(Credential.domain == domain.lower())
        async with db.session() as s:
            rows = (await s.execute(stmt.limit(limit))).scalars().all()
        return {
            "credentials": [
                {"email": c.email, "domain": c.domain, "page_url": c.page_url} for c in rows
            ]
        }

    @app.get("/listings", dependencies=auth)
    async def list_listings(
        vendor: str | None = None,
        max_price: float | None = None,
        limit: int = Query(50, le=500),
    ) -> dict:
        stmt = sa.select(Listing)
        if vendor:
            stmt = stmt.where(Listing.vendor == vendor)
        if max_price is not None:
            stmt = stmt.where(Listing.price <= max_price)
        async with db.session() as s:
            rows = (await s.execute(stmt.limit(limit))).scalars().all()
        return {
            "listings": [
                {
                    "product": r.product, "vendor": r.vendor, "price": r.price,
                    "currency": r.currency, "page_url": r.page_url,
                    "context": r.context,
                }
                for r in rows
            ]
        }

    # --- watchlists / alerts ---------------------------------------------

    @app.get("/watchlists", dependencies=auth)
    async def list_watchlists() -> dict:
        async with db.session() as s:
            rows = (await s.execute(sa.select(Watchlist))).scalars().all()
        return {"watchlists": [_watchlist(w) for w in rows]}

    @app.post("/watchlists", dependencies=admin)
    async def create_watchlist(payload: dict) -> dict:
        kind = payload.get("kind")
        value = payload.get("value")
        if kind not in KINDS or not value:
            raise HTTPException(
                status_code=400, detail=f"kind ({'|'.join(KINDS)}) + value required"
            )
        if kind == "event":
            event_kind, _ = parse_event_value(value)
            if event_kind not in (*ALL_EVENT_KINDS, "notable"):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"unknown event kind {event_kind!r} — use one of: "
                        f"{', '.join((*ALL_EVENT_KINDS, 'notable'))}, optionally @hostname"
                    ),
                )
        webhook_url = payload.get("webhook_url") or None
        if webhook_url:
            # Reject at creation so the operator finds out now, not from a
            # warning buried in the worker log on the first delivery attempt.
            try:
                await check_url(webhook_url)
            except UnsafeDestination as exc:
                raise HTTPException(
                    status_code=400, detail=f"webhook_url rejected: {exc}"
                ) from None
        wl = Watchlist(
            name=payload.get("name") or f"{kind}:{value}",
            kind=kind,
            value=value,
            webhook_url=webhook_url,
        )
        async with db.session() as s:
            s.add(wl)
            await s.commit()
            await s.refresh(wl)
        return _watchlist(wl)

    @app.delete("/watchlists/{watchlist_id}", dependencies=admin)
    async def delete_watchlist(watchlist_id: int) -> dict:
        async with db.session() as s:
            await s.execute(sa.delete(Watchlist).where(Watchlist.id == watchlist_id))
            await s.commit()
        return {"deleted": watchlist_id}

    @app.post("/watchlists/evaluate", dependencies=admin)
    async def run_watchlists() -> dict:
        return await evaluate_watchlists(db)

    @app.get("/alerts", dependencies=auth)
    async def list_alerts(limit: int = Query(50, le=500)) -> dict:
        async with db.session() as s:
            rows = (
                await s.execute(
                    sa.select(Alert, Watchlist)
                    .join(Watchlist, Alert.watchlist_id == Watchlist.id)
                    .order_by(Alert.created_at.desc())
                    .limit(limit)
                )
            ).all()
        return {
            "alerts": [
                {
                    "watchlist_id": a.watchlist_id, "watchlist": w.name, "kind": w.kind,
                    "page_url": a.page_url, "matched_value": a.matched_value,
                    "delivered": a.delivered,
                }
                for a, w in rows
            ]
        }

    # --- crawl control (for the GUI Start button) ------------------------

    crawl_state: dict = {"running": False, "stats": None, "error": None, "seeds": 0}
    current: dict = {"crawler": None}  # live handle, for stop + progress

    def scope_settings(payload):
        try:
            seeds = payload.get("seeds") or []
            if not isinstance(seeds, list) or not all(isinstance(s, str) for s in seeds):
                raise ValueError("Seeds must be a list of URLs")
            seeds = [s.strip() for s in seeds if s.strip()]
            if not seeds:
                raise ValueError("Provide at least one seed URL")
            hosts = canonical_hosts(payload.get("allowed_hosts") or [])
            strict = bool(payload.get("strict_scope", settings.strict_scope))
            if strict and not hosts:
                hosts = sorted({valid_host(s) for s in seeds})
            hosts = hosts or settings.allowed_hosts
            if not all(allows(s, hosts) for s in seeds):
                raise ValueError("A seed is outside allowed hosts")
            depth = int(payload.get("max_depth", settings.max_depth))
            pages = int(payload.get("max_pages", settings.max_pages))
            if not 0 <= depth <= 100 or not 1 <= pages <= 100_000:
                raise ValueError("Depth must be 0–100; pages must be 1–100000")
            return seeds, hosts, strict, depth, pages
        except (ValueError, TypeError, AttributeError, ScopeError) as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/admin/crawl-preview", dependencies=admin)
    async def preview_crawl(payload: dict):
        seeds, hosts, strict, depth, pages = scope_settings(payload)
        async with db.session() as s:
            eligible = sa.select(sa.func.count()).select_from(Page).where(Page.depth <= depth)
            if hosts:
                eligible = eligible.where(Page.hostname.in_(hosts))
            count = await s.scalar(eligible)
        return {"seeds": seeds, "allowed_hosts": hosts, "strict_scope": bool(hosts),
                "max_depth": depth, "max_pages": pages, "existing_pages_in_scope": count,
                "redirects": "Every redirect must remain within allowed hosts" if hosts else
                    "Unrestricted hosts; priority pinning is not a boundary",
                "note": "Depth and scope also apply to the existing shared queue. Other worker processes retain their own configuration."}

    async def _bg_crawl(run_settings: Settings, seeds: list[str], pin: bool = False) -> None:
        crawl_state.update(running=True, error=None, stats=None, seeds=len(seeds))
        fetcher = None
        try:
            crawler, fetcher = await asyncio.to_thread(build_crawler, run_settings, db)
            current["crawler"] = crawler
            # Recorded like any other pass: a crawl started from the GUI is still
            # collection, and leaving it out of the run log would put a hole in
            # the health picture exactly when someone is watching it most closely.
            async with record_run(db, trigger="api", settings=run_settings) as run:
                # force_seeds: the user explicitly asked for these URLs, so re-crawl
                # them now even if a previous attempt failed and set a backoff.
                stats = await crawler.run(seeds, force_seeds=True, pin_seeds=pin)
                alerts = await evaluate_watchlists(db)
                crawl_state["stats"] = stats
                run.pages_crawled = stats["crawled"]
                run.pages_dead = stats["dead"]
                run.processing_errors = stats.get("processing_errors", 0)
                run.iocs_found = stats["iocs"]
                run.new_alerts = alerts["new_alerts"]
        except Exception as exc:  # noqa: BLE001 - surface any crawl error to the UI
            crawl_state["error"] = str(exc)
            log.exception("background crawl failed")
        finally:
            if fetcher is not None:
                await fetcher.aclose()
            current["crawler"] = None
            crawl_state["running"] = False

    @app.post("/admin/crawl", dependencies=admin)
    async def start_crawl(payload: dict) -> dict:
        if settings.preview_mode:
            raise HTTPException(409, "Synthetic preview: use the normal server for real collection")
        if crawl_state["running"]:
            raise HTTPException(status_code=409, detail="a crawl is already running")
        seeds, hosts, strict, depth, pages = scope_settings(payload)
        run_settings = settings.model_copy(deep=True)
        run_settings.allowed_hosts = hosts
        run_settings.strict_scope = strict
        run_settings.max_depth, run_settings.max_pages = depth, pages
        run_settings.store_html = bool(payload.get("store_html", settings.store_html))
        # NB: check "is not None", not truthiness — max_depth=0 ("seeds only") is a
        # legitimate value, and treating it as absent would silently spider deeper
        # than asked. Omitted/blank fields fall back to the configured defaults.
        if payload.get("max_pages") is not None:
            run_settings.max_pages = max(1, int(payload["max_pages"]))
        if payload.get("max_depth") is not None:
            run_settings.max_depth = max(0, int(payload["max_depth"]))
        if payload.get("focus"):
            run_settings.focus_keywords = [
                k.strip() for k in str(payload["focus"]).split(",") if k.strip()
            ]
        if payload.get("allow_clearnet"):
            run_settings.allow_clearnet = True
        if payload.get("llm"):
            run_settings.llm_enabled = True
        crawl_state["running"] = True
        asyncio.create_task(_bg_crawl(run_settings, seeds, pin=bool(payload.get("pin"))))
        return {"started": True, "seeds": len(seeds)}

    @app.get("/admin/crawl-status", dependencies=auth)
    async def get_crawl_status() -> dict:
        state = dict(crawl_state)
        crawler = current["crawler"]
        if crawler is not None and crawl_state["running"]:
            state["live"] = {  # progress while the crawl is still going
                "crawled": crawler.pages_crawled,
                "iocs": crawler.iocs_found,
                "dead": crawler.pages_dead,
                "blocked": crawler.pages_blocked,
            }
        return state

    @app.post("/admin/crawl/stop", dependencies=admin)
    async def stop_crawl() -> dict:
        crawler = current["crawler"]
        if crawler is None or not crawl_state["running"]:
            raise HTTPException(status_code=409, detail="no crawl is running")
        crawler.request_stop()
        return {"stopping": True}

    @app.delete("/admin/queue", dependencies=admin)
    async def clear_queue() -> dict:
        """Drop links that were discovered but never fetched. Crawled pages and
        everything extracted from them are untouched."""
        async with db.session() as s:
            urls = (
                await s.execute(sa.select(Page.url).where(Page.status == "discovered"))
            ).scalars().all()
            if urls:
                await s.execute(sa.delete(Page).where(Page.url.in_(urls)))
                await s.commit()
        return {"removed": len(urls)}

    @app.get("/sites", dependencies=auth)
    async def list_sites(limit: int = Query(200, le=1000)) -> dict:
        """Every host seen, with how much of it we've actually fetched — the
        view you need to decide what's worth crawling next."""
        async with db.session() as s:
            rows = (
                await s.execute(
                    sa.select(Page.hostname, Page.status, sa.func.count())
                    .where(Page.hostname.isnot(None))
                    .group_by(Page.hostname, Page.status)
                )
            ).all()
            ioc_rows = (
                await s.execute(
                    sa.select(Page.hostname, sa.func.count(Ioc.id))
                    .join(Ioc, Ioc.page_url == Page.url)
                    .where(Page.hostname.isnot(None))
                    .group_by(Page.hostname)
                )
            ).all()
            pinned_hosts = set(
                (
                    await s.execute(
                        sa.select(Page.hostname).where(Page.pinned.is_(True)).distinct()
                    )
                ).scalars()
            )
            # Previously good pages that have started failing are still "crawled"
            # (content retained) but are not answering; count them as unreachable.
            failing_by_host = dict(
                (
                    await s.execute(
                        sa.select(Page.hostname, sa.func.count())
                        .where(Page.hostname.isnot(None), Page.status == "crawled",
                               not_answering())
                        .group_by(Page.hostname)
                    )
                ).all()
            )
        iocs_by_host = dict(ioc_rows)
        sites: dict[str, dict] = {}
        for host, status, n in rows:
            site = sites.setdefault(
                host,
                {"host": host, "crawled": 0, "queued": 0, "unreachable": 0,
                 "pinned": host in pinned_hosts},
            )
            if status == "crawled":
                site["crawled"] += n
            elif status == "discovered":
                site["queued"] += n
            elif status == "dead":
                site["unreachable"] += n
        for host, site in sites.items():
            site["iocs"] = iocs_by_host.get(host, 0)
            site["unreachable"] += failing_by_host.get(host, 0)
        ordered = sorted(sites.values(), key=lambda x: (-x["crawled"], -x["iocs"], x["host"]))
        return {"sites": ordered[:limit], "total": len(ordered)}

    @app.get("/export/evidence.zip", dependencies=auth)
    async def export_evidence(
        host: str | None = None,
        url: str | None = None,
        case: str | None = None,
        limit: int = Query(200, le=2000),
    ) -> Response:
        """Captured pages plus a manifest of hashes and capture times.

        Read the bundle's README before relying on it: it records what was
        captured and when, but is not notarised, and the capture-time hash covers
        the raw response body rather than the extracted text.
        """
        content, summary = await build_evidence_bundle(
            db, host=host, url=url, limit=limit, case_name=case,
            signing_key=settings.evidence_signing_key,
        )
        if not summary["items"]:
            raise HTTPException(status_code=404, detail="no stored pages matched")
        name = _SAFE_FILENAME.sub("-", case or host or "umbra").strip("-") or "umbra"
        return Response(
            content=content,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="evidence-{name}.zip"',
                "X-Umbra-Items": str(summary["items"]),
                "X-Umbra-Verifiable-Bodies": str(summary["verifiable_bodies"]),
            },
        )

    @app.get("/export/stix", dependencies=auth)
    async def export_stix(
        type: str | None = None,
        attribution_only: bool = False,
        limit: int = Query(10_000, le=50_000),
        download: bool = False,
    ) -> Response:
        """STIX 2.1 bundle for ingest into MISP, OpenCTI or any TAXII-fed TIP.

        ``attribution_only=true`` restricts to identifiers that point at whoever
        is selling, leaving breach-victim data out of a feed that a customer will
        treat as actor infrastructure.
        """
        bundle = await build_stix_bundle(
            db, ioc_type=type, attribution_only=attribution_only, limit=limit
        )
        headers = (
            {"Content-Disposition": 'attachment; filename="umbra-stix.json"'}
            if download else {}
        )
        return Response(
            content=json.dumps(bundle, indent=2),
            media_type="application/stix+json;version=2.1",
            headers=headers,
        )

    @app.get("/export/iocs.csv", dependencies=auth)
    async def export_iocs(type: str | None = None) -> Response:
        """Download indicators as CSV — the quick way to get data into another tool."""
        stmt = _filter_ioc_type(sa.select(Ioc.ioc_type, Ioc.value, Ioc.page_url), type)
        async with db.session() as s:
            rows = (await s.execute(stmt)).all()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["type", "value", "page_url"])
        writer.writerows(rows)
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="umbra-indicators.csv"'},
        )

    @app.post("/admin/resolve-actors", dependencies=admin)
    async def run_resolve() -> dict:
        return await resolve_actors(db)

    @app.post("/admin/reprocess", dependencies=admin)
    async def run_reprocess() -> dict:
        """Re-extract indicators/credentials/listings from stored page text —
        use after an extractor improves, instead of re-crawling."""
        return await reprocess_pages(db, build_enrichers(settings))

    @app.get("/sources", dependencies=auth)
    async def get_sources() -> dict:
        """Available source packs — curated coverage you can queue in one click."""
        return {
            "packs": [p.to_dict() for p in available_packs(settings.source_packs_path)]
        }

    @app.post("/admin/seed-pack", dependencies=admin)
    async def seed_source_pack(payload: dict) -> dict:
        name = (payload or {}).get("pack")
        if not name:
            raise HTTPException(status_code=400, detail="pack required")
        try:
            return await seed_pack(db, settings, name, force=bool(payload.get("force")))
        except KeyError:
            raise HTTPException(status_code=404, detail=f"no source pack {name!r}") from None

    @app.post("/admin/rescore-queue", dependencies=admin)
    async def run_rescore() -> dict:
        """Re-prioritise already-queued links with the current scorer. Links keep
        the score they were discovered with, so a scorer change is otherwise
        invisible to everything already in the frontier."""
        _, scorer = build_scorer(settings)
        return await rescore_frontier(db, scorer, off_host_factor=settings.off_host_priority)

    @app.post("/admin/backfill-timeline", dependencies=admin)
    async def run_backfill() -> dict:
        """Seed the timeline from pages crawled before it existed. Idempotent."""
        return await backfill_timeline(db)

    @app.post("/admin/reembed", dependencies=admin)
    async def run_reembed() -> dict:
        """Rebuild page embeddings with the active embedder — run after switching
        models, otherwise the existing vectors stay invisible to search."""
        return await reembed_pages(db, embedder)

    # --- the GUI ---------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def ui() -> FileResponse:
        return FileResponse(
            _UI_FILE,
            # Revalidate on every load (ETag makes that a cheap 304). Without this a
            # browser kept showing the previous build of the GUI after an upgrade
            # until a hard refresh, which reads as "the fix didn't work".
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/workspace.js", include_in_schema=False)
    async def workspace_script():
        return FileResponse(_UI_FILE.parent / "workspace.js", media_type="application/javascript")

    @app.get("/investigations.js", include_in_schema=False)
    async def investigations_script():
        return FileResponse(_UI_FILE.parent / "investigations.js",
                            headers={"Cache-Control": "no-cache"})

    @app.get("/quality", dependencies=auth)
    async def quality_report():
        from ..evaluation import evaluate
        return await evaluate()

    return app


def _page_summary(p: Page) -> dict:
    return {
        "url": p.url,
        "hostname": p.hostname,
        "title": p.title,
        "status": p.status,
        "page_type": p.page_type,
        "threat_category": p.threat_category,
        "summary": p.summary,
        "language": p.language,
    }


def _watchlist(w: Watchlist) -> dict:
    return {
        "id": w.id, "name": w.name, "kind": w.kind, "value": w.value,
        "webhook_url": w.webhook_url, "active": w.active,
    }
