"""Command-line entrypoint (``umbra ...`` or ``python -m umbra``)."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import signal

import sqlalchemy as sa
import typer

from .alerting import KINDS, evaluate_watchlists
from .config import Settings
from .db import Database
from .factory import build_crawler, build_enrichers, build_scorer
from .intel.embeddings import build_embedder, search
from .intel.entities import resolve_actors
from .logging import configure_logging, get_logger
from .models import ApiKey, Watchlist
from .netguard import UnsafeDestination, check_url
from .reprocess import reembed_pages, reprocess_pages, rescore_frontier
from .retention import purge_expired
from .runs import health as collection_health
from .sourcegen import generate as generate_source_packs
from .sources import available as available_packs
from .sources import get as get_pack
from .sources import seed_pack
from .runs import list_runs, purge_old_runs, reap_abandoned_runs, record_run
from .timeline import backfill as backfill_timeline
from .timeline import host_liveness, list_events

app = typer.Typer(add_completion=False, help="Umbra — dark-web intelligence platform")


@app.command()
def crawl(
    seeds: list[str] = typer.Argument(None, help="Seed URLs"),
    seed_file: str = typer.Option(None, "--seed-file", help="File of seed URLs, one per line"),
    max_pages: int = typer.Option(None, help="Stop after N crawled pages"),
    max_depth: int = typer.Option(None, help="Max link expansion depth"),
    workers: int = typer.Option(None, help="Concurrent workers"),
    focus: str = typer.Option(None, help="Comma-separated focus keywords (enables focused crawling)"),
    allow_clearnet: bool = typer.Option(False, help="Also crawl non-.onion links"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM enrichment (needs ANTHROPIC_API_KEY)"),
    pin: bool = typer.Option(
        False, "--pin",
        help="Treat seeds as targets: stay on their hosts, demote links to other sites",
    ),
) -> None:
    """Crawl from one or more seed URLs through Tor. Resumes an existing DB."""
    settings = Settings()
    if max_pages is not None:
        settings.max_pages = max_pages
    if max_depth is not None:
        settings.max_depth = max_depth
    if workers is not None:
        settings.max_workers = workers
    if focus:
        settings.focus_keywords = [k.strip() for k in focus.split(",") if k.strip()]
    if allow_clearnet:
        settings.allow_clearnet = True
    if llm:
        settings.llm_enabled = True

    seed_list = list(seeds or [])
    if seed_file:
        with open(seed_file, encoding="utf-8") as fh:
            seed_list.extend(line.strip() for line in fh if line.strip())
    if not seed_list:
        raise typer.BadParameter("Provide at least one seed URL or --seed-file")

    asyncio.run(_run_crawl(settings, seed_list, pin))


@app.command("search")
def search_cmd(
    query: str = typer.Argument(..., help="Natural-language query"),
    top_k: int = typer.Option(10, "--top-k", help="Number of results"),
) -> None:
    """Semantic search over crawled pages."""
    asyncio.run(_run_search(Settings(), query, top_k))


@app.command("resolve-actors")
def resolve_actors_cmd() -> None:
    """Rebuild the threat-actor graph from extracted identifiers."""
    asyncio.run(_run_resolve(Settings()))


@app.command()
def reprocess() -> None:
    """Re-extract from stored pages (after improving an extractor) — no re-crawl."""
    asyncio.run(_run_reprocess(Settings()))


@app.command()
def reembed() -> None:
    """Rebuild embeddings for stored pages — run after changing the embedder."""
    asyncio.run(_run_reembed(Settings()))


@app.command()
def timeline(
    limit: int = typer.Option(30, help="How many events to show"),
    notable: bool = typer.Option(False, help="Only outages, recoveries and new identifiers"),
    host: str = typer.Option(None, help="Restrict to one hidden service"),
) -> None:
    """Show what changed: outages, recoveries, content changes, new identifiers."""
    asyncio.run(_run_timeline(Settings(), limit, notable, host))


@app.command()
def runs(limit: int = typer.Option(15, help="How many passes to show")) -> None:
    """Collection health: is the crawler actually doing anything?"""
    asyncio.run(_run_runs(Settings(), limit))


@app.command()
def liveness() -> None:
    """Per-service up/down state, offline services first."""
    asyncio.run(_run_liveness(Settings()))


@app.command("sources")
def sources_cmd(
    seed: str = typer.Option(None, "--seed", help="Queue this pack's sources for crawling"),
    show: str = typer.Option(None, "--show", help="List the sources in a pack"),
    generate_to: str = typer.Option(
        None, "--generate", help="Write packs derived from this database's own results"
    ),
) -> None:
    """List, inspect, seed, or generate source packs (curated coverage)."""
    asyncio.run(_run_sources(Settings(), seed, show, generate_to))


@app.command("rescore-queue")
def rescore_queue() -> None:
    """Re-prioritise queued links with the current scorer (after changing focus)."""
    asyncio.run(_run_rescore(Settings()))


@app.command("backfill-timeline")
def backfill_timeline_cmd() -> None:
    """Seed the timeline from pages crawled before it existed. Idempotent."""
    asyncio.run(_run_backfill(Settings()))


@app.command()
def watch(
    kind: str = typer.Argument(..., help="keyword | domain | email | ioc | event"),
    value: str = typer.Argument(
        ...,
        help=(
            "What to watch for. For kind=event: an event kind (page_unreachable, "
            "page_recovered, indicator_new, page_changed, page_new) or 'notable', "
            "optionally scoped with @hostname"
        ),
    ),
    name: str = typer.Option(None, help="Human-readable name"),
    webhook: str = typer.Option(None, help="Webhook URL to POST alerts to"),
) -> None:
    """Add a watchlist entry.

    Content watchlists fire when something appears in the corpus; event
    watchlists fire when something *changes* — e.g.
    `umbra watch event page_unreachable@market.onion` to be told when a specific
    marketplace stops responding.
    """
    if kind not in KINDS:
        raise typer.BadParameter(f"kind must be one of: {', '.join(KINDS)}")
    asyncio.run(_run_watch(Settings(), kind, value, name, webhook))


@app.command()
def apikey(
    name: str = typer.Option("default", help="Label for the key"),
    role: str = typer.Option("viewer", help="viewer (read) | admin (manage)"),
) -> None:
    """Create an API key for the query service."""
    if role not in ("viewer", "admin"):
        raise typer.BadParameter("role must be 'viewer' or 'admin'")
    asyncio.run(_run_apikey(Settings(), name, role))


@app.command("apikey-list")
def apikey_list() -> None:
    """List API keys — names and roles, never the secrets."""
    asyncio.run(_run_apikey_list(Settings()))


@app.command("apikey-revoke")
def apikey_revoke(name: str = typer.Argument(..., help="Name of the key to deactivate")) -> None:
    """Deactivate an API key. Do this to the bootstrap key once you have your own."""
    asyncio.run(_run_apikey_revoke(Settings(), name))


@app.command()
def purge(
    days: int = typer.Option(None, help="Delete pages older than N days (default: retention_days)"),
) -> None:
    """Delete pages (and their derived records) past the retention window."""
    settings = Settings()
    asyncio.run(_run_purge(settings, days if days is not None else settings.retention_days))


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
) -> None:
    """Run the FastAPI query + alerting service (needs the [api] extra)."""
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise typer.BadParameter('API deps missing — install with: pip install -e ".[api]"') from exc
    from .api import create_app

    # Anything but loopback is reachable from the network: never start open
    # there, whatever the database currently says about keys.
    public = host not in ("127.0.0.1", "localhost", "::1")
    uvicorn.run(create_app(Settings(), public=public), host=host, port=port)


@app.command()
def worker(
    seed_file: str = typer.Option(None, "--seed-file", help="File of seed URLs, one per line"),
    seeds: list[str] = typer.Argument(None, help="Seed URLs"),
    interval: int = typer.Option(600, help="Seconds to sleep between crawl passes"),
    once: bool = typer.Option(False, help="Run a single pass then exit"),
) -> None:
    """Run continuously: crawl (resume + recrawl due pages) -> alert -> purge -> sleep.

    This is the long-running service process (the Docker `worker`). Exits cleanly
    on SIGTERM/SIGINT.
    """
    settings = Settings()
    seed_list = list(seeds or [])
    if seed_file:
        with open(seed_file, encoding="utf-8") as fh:
            seed_list.extend(line.strip() for line in fh if line.strip())
    asyncio.run(_run_worker(settings, seed_list, interval, once))


@app.command("init-db")
def init_db() -> None:
    """Create database tables and exit."""
    asyncio.run(_init_db(Settings()))


async def _run_crawl(settings: Settings, seeds: list[str], pin: bool = False) -> None:
    configure_logging(settings.log_level)
    log = get_logger("cli")
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    crawler, fetcher = build_crawler(settings, db)
    try:
        # explicit user request: force even if recently crawled/failed
        stats = await crawler.run(seeds, force_seeds=True, pin_seeds=pin)
        log.info("done: %s", stats)
        alert_stats = await evaluate_watchlists(db)
        if alert_stats["new_alerts"]:
            log.info("alerts: %s", alert_stats)
    finally:
        await fetcher.aclose()
        await db.dispose()


async def _run_worker(settings: Settings, seeds: list[str], interval: int, once: bool) -> None:
    configure_logging(settings.log_level)
    log = get_logger("worker")
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    crawler, fetcher = build_crawler(settings, db)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):  # not supported on Windows
            loop.add_signal_handler(sig, stop.set)

    # A previous worker that was killed mid-pass leaves its run row open.
    await reap_abandoned_runs(db)

    log.info("worker starting (interval=%ss, %d seed(s))", interval, len(seeds))
    try:
        while not stop.is_set():
            async with record_run(db, trigger="worker", settings=settings) as run:
                stats = await crawler.run(seeds)
                alerts = await evaluate_watchlists(db)
                # Rebuild the actor graph every pass. Entity resolution is a batch
                # over the whole IOC table, so it does not update itself as a crawl
                # discovers identifiers — and nothing else in this loop triggers it.
                # Left out, actors silently freeze at whatever the last manual run
                # produced while the evidence underneath keeps growing: observed on a
                # live corpus sitting at 2 actors when the data supported 13.
                actors = await resolve_actors(db)
                if settings.retention_days > 0:
                    await purge_expired(db, settings.retention_days)
                if settings.run_retention_days > 0:
                    await purge_old_runs(db, settings.run_retention_days)
                run.pages_crawled = stats["crawled"]
                run.pages_dead = stats["dead"]
                run.processing_errors = stats.get("processing_errors", 0)
                run.iocs_found = stats["iocs"]
                run.new_alerts = alerts["new_alerts"]
                run.actors = actors["actors"]
            log.info(
                "pass complete: crawl=%s alerts=%s actors=%s", stats, alerts, actors
            )

            # Say it out loud. The failure this guards against produced perfectly
            # healthy-looking output while collecting nothing, so the warning has
            # to come from something that checks the outcome, not the log line.
            verdict = await collection_health(db, settings.health_stale_after_s)
            if verdict["status"] in ("stalled", "failing", "stale"):
                log.warning("COLLECTION %s — %s", verdict["status"].upper(), verdict["detail"])
            elif verdict["status"] == "idle":
                log.info("collection idle — %s", verdict["detail"])

            if once:
                break
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)
    finally:
        log.info("worker shutting down")
        await fetcher.aclose()
        await db.dispose()


async def _run_search(settings: Settings, query: str, top_k: int) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    embedder = build_embedder(settings)
    try:
        results = await search(db, embedder, query, top_k=top_k)
        if not results:
            typer.echo("No results (crawl some pages first, with embeddings enabled).")
            return
        for r in results:
            typer.echo(f"{r['score']:.3f}  {r['url']}")
            if r["title"]:
                typer.echo(f"        {r['title']}")
    finally:
        await db.dispose()


async def _run_resolve(settings: Settings) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        summary = await resolve_actors(db)
        typer.echo(f"resolved {summary['actors']} actors from {summary['identifiers']} identifiers")
    finally:
        await db.dispose()


async def _run_reprocess(settings: Settings) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        r = await reprocess_pages(db, build_enrichers(settings))
        typer.echo(f"re-extracted {r['records']} record(s) from {r['pages']} stored page(s)")
    finally:
        await db.dispose()


async def _run_reembed(settings: Settings) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        embedder = build_embedder(settings)
        r = await reembed_pages(db, embedder)
        typer.echo(f"re-embedded {r['pages']} page(s) with {r['embedder']} (dim {r['dim']})")
    finally:
        await db.dispose()


async def _run_timeline(settings: Settings, limit: int, notable: bool, host: str | None) -> None:
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        events = await list_events(db, host=host, notable_only=notable, limit=limit)
        if not events:
            typer.echo("No events yet — the timeline fills in as recrawls detect changes.")
            return
        for e in events:
            when = (e["at"] or "")[:19].replace("T", " ")
            typer.echo(f"{when}  {e['label']:<20} {e['summary']}")
            if e["detail"]:
                typer.echo(f"{'':19}  {'':<20} {e['detail'][:96]}")
    finally:
        await db.dispose()


async def _run_sources(settings: Settings, seed: str | None, show: str | None, generate_to: str | None) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        if generate_to:
            await db.create_all()
            written = await generate_source_packs(db, generate_to)
            for name, n in written.items():
                typer.echo(f"wrote {name}: {n} source(s) -> {generate_to}")
            return
        if show:
            pack = get_pack(show, settings.source_packs_path)
            if pack is None:
                raise typer.BadParameter(f"no source pack named {show!r}")
            typer.echo(f"{pack.name} ({pack.category}, v{pack.version}) — {pack.description}")
            for source in pack.sources:
                typer.echo(f"  {source.url}")
                detail = " | ".join(x for x in (source.note, source.evidence, source.last_seen) if x)
                if detail:
                    typer.echo(f"      {detail}")
            return
        if seed:
            await db.create_all()
            try:
                result = await seed_pack(db, settings, seed)
            except KeyError:
                raise typer.BadParameter(f"no source pack named {seed!r}") from None
            typer.echo(
                f"queued {result['queued']} of {result['sources']} source(s) from {seed!r}"
            )
            return

        packs = available_packs(settings.source_packs_path)
        if not packs:
            typer.echo("No source packs found.")
            return
        for pack in packs:
            typer.echo(f"{pack.name:24} {pack.category:12} {len(pack.sources):4} sources  ({pack.origin})")
            typer.echo(f"    {pack.description[:96]}")
    finally:
        await db.dispose()


async def _run_rescore(settings: Settings) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        _, scorer = build_scorer(settings)
        r = await rescore_frontier(db, scorer, off_host_factor=settings.off_host_priority)
        typer.echo(f"rescored {r['rescored']} of {r['queued']} queued link(s)")
    finally:
        await db.dispose()


async def _run_backfill(settings: Settings) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    try:
        r = await backfill_timeline(db)
        typer.echo(f"reconstructed {r['events']} historical event(s) from stored page state")
    finally:
        await db.dispose()


async def _run_runs(settings: Settings, limit: int) -> None:
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    try:
        verdict = await collection_health(db, settings.health_stale_after_s)
        typer.echo(f"COLLECTION: {verdict['status'].upper()} — {verdict['detail']}")
        rows = await list_runs(db, limit=limit)
        if not rows:
            return
        typer.echo("")
        typer.echo(f"{'started':<20}{'status':<9}{'pages':>7}{'dead':>6}{'iocs':>6}{'events':>8}  waiting")
        for r in rows:
            flag = "  <- STALLED" if r["stalled"] else ""
            typer.echo(
                f"{(r['started_at'] or '')[:19].replace('T',' '):<20}"
                f"{r['status']:<9}{r['pages_crawled']:>7}{r['pages_dead']:>6}"
                f"{r['iocs_found']:>6}{r['events_emitted']:>8}  {r['work_waiting']}{flag}"
            )
    finally:
        await db.dispose()


async def _run_liveness(settings: Settings) -> None:
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        for h in await host_liveness(db):
            since = f"  since {h['offline_since'][:19].replace('T', ' ')}" if h["offline_since"] else ""
            typer.echo(f"{h['state']:<8} {h['host'][:56]:<58} {h['live']}/{h['known']} live{since}")
    finally:
        await db.dispose()


async def _run_watch(settings: Settings, kind: str, value: str, name, webhook) -> None:
    if webhook:
        try:
            await check_url(webhook)
        except UnsafeDestination as exc:
            raise typer.BadParameter(f"webhook rejected: {exc}") from None
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    try:
        async with db.session() as s:
            s.add(Watchlist(name=name or f"{kind}:{value}", kind=kind, value=value, webhook_url=webhook))
            await s.commit()
        typer.echo(f"watchlist added: {kind}={value}" + (f" -> {webhook}" if webhook else ""))
    finally:
        await db.dispose()


async def _run_apikey(settings: Settings, name: str, role: str) -> None:
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    key = secrets.token_hex(24)
    try:
        async with db.session() as s:
            s.add(ApiKey(key=key, name=name, role=role))
            await s.commit()
        typer.echo(f"API key created ({name}, role={role}): {key}")
        typer.echo("Send it as the  X-API-Key  header.")
    finally:
        await db.dispose()


async def _run_apikey_list(settings: Settings) -> None:
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    try:
        async with db.session() as s:
            keys = (await s.execute(sa.select(ApiKey).order_by(ApiKey.id))).scalars().all()
        if not keys:
            typer.echo("No API keys — the service runs open on loopback only.")
            return
        for k in keys:
            state = "active" if k.active else "revoked"
            typer.echo(f"{k.id:>4}  {k.name:<24} {k.role:<7} {state}  ...{k.key[-6:]}")
    finally:
        await db.dispose()


async def _run_apikey_revoke(settings: Settings, name: str) -> None:
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    try:
        async with db.session() as s:
            targets = (
                await s.execute(
                    sa.select(ApiKey).where(ApiKey.name == name, ApiKey.active.is_(True))
                )
            ).scalars().all()
            if not targets:
                raise typer.BadParameter(f"no active key named {name!r}")
            # Revoking the last admin key would leave the service either open
            # (loopback) or minting a fresh bootstrap key on next start (public):
            # both are surprises. Make the operator create the replacement first.
            remaining_admins = (
                await s.execute(
                    sa.select(sa.func.count())
                    .select_from(ApiKey)
                    .where(ApiKey.active.is_(True), ApiKey.role == "admin", ApiKey.name != name)
                )
            ).scalar_one()
            if any(k.role == "admin" for k in targets) and remaining_admins == 0:
                raise typer.BadParameter(
                    f"{name!r} is the last active admin key — create another first "
                    "(umbra apikey --role admin), then revoke this one"
                )
            for k in targets:
                k.active = False
            await s.commit()
        typer.echo(f"revoked {len(targets)} key(s) named {name!r}")
    finally:
        await db.dispose()


async def _run_purge(settings: Settings, days: int) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    try:
        result = await purge_expired(db, days)
        typer.echo(f"purged {result['purged_pages']} expired page(s)")
    finally:
        await db.dispose()


async def _init_db(settings: Settings) -> None:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, echo=settings.db_echo)
    await db.create_all()
    await db.dispose()
    get_logger("cli").info("database ready: %s", settings.database_url)


if __name__ == "__main__":
    app()
