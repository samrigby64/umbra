"""The intelligence timeline: what changed, and when.

Crawling tells you what the dark web looks like *now*. Analysts are paid for the
delta — a marketplace that stopped answering, a vendor whose PGP key suddenly
differs, a service that came back three weeks after a takedown. Because every
recrawl overwrites the previous state, those transitions have to be recorded at
the instant they are detected or they are gone for good.

Events are emitted from ``Scheduler.complete()`` inside the same transaction that
applies the state change, so the log can never claim something the database
disagrees with, and a rolled-back crawl leaves no phantom events behind.

Only *transitions* are recorded, never steady state. A page that is fetched a
hundred times unchanged produces zero events; the timeline stays readable because
silence is the default.
"""

from __future__ import annotations

import sqlalchemy as sa

from .db import Database
from .logging import get_logger
from .models import Event, Page

log = get_logger("timeline")

# --- event kinds -----------------------------------------------------------
PAGE_NEW = "page_new"                  # first successful fetch of a URL
PAGE_CHANGED = "page_changed"          # content hash differs from last crawl
PAGE_UNREACHABLE = "page_unreachable"  # previously good page stopped answering
PAGE_RECOVERED = "page_recovered"      # ...and later started answering again
PAGE_DEAD = "page_dead"                # given up on after repeated failures
INDICATOR_NEW = "indicator_new"        # a new actor identifier appeared on a page

# Kinds an analyst should look at first: something is materially different about
# a service or the person running it, as opposed to routine content churn.
NOTABLE = (PAGE_UNREACHABLE, PAGE_RECOVERED, PAGE_DEAD, INDICATOR_NEW)

ALL_KINDS = (PAGE_NEW, PAGE_CHANGED, PAGE_UNREACHABLE, PAGE_RECOVERED, PAGE_DEAD, INDICATOR_NEW)

_KIND_LABELS = {
    PAGE_NEW: "New page",
    PAGE_CHANGED: "Content changed",
    PAGE_UNREACHABLE: "Stopped responding",
    PAGE_RECOVERED: "Back online",
    PAGE_DEAD: "Given up as dead",
    INDICATOR_NEW: "New identifier",
}



def not_answering():
    """SQL condition: pages whose most recent fetch failed.

    That is permanently-dead pages *and* previously good pages that have started
    failing. The latter keep ``status == "crawled"`` on purpose (their archived
    content must survive a transient outage), so any count keyed on status alone
    silently reports every fresh outage as healthy. Every view that says whether
    something is reachable must use this one definition.
    """
    return sa.or_(
        Page.status == "dead",
        sa.and_(Page.status == "crawled", sa.func.coalesce(Page.consecutive_failures, 0) > 0),
    )

def label(kind: str) -> str:
    return _KIND_LABELS.get(kind, kind)


# Events that describe whether a page is reachable, newest of which is the page's
# current liveness state.
_LIVENESS_KINDS = (PAGE_NEW, PAGE_UNREACHABLE, PAGE_RECOVERED, PAGE_DEAD)


async def is_offline(session, page_url: str) -> bool:
    """Whether the last thing we recorded about ``page_url`` was an outage.

    Deliberately read from the event log rather than ``Page.consecutive_failures``.
    That counter is reset whenever an operator force-crawls a URL — correct for
    scheduling, wrong for history: keyed off it, one continuous outage would log a
    fresh "stopped responding" on every manual retry, and a recovery following a
    forced crawl would go unrecorded because the counter had already been zeroed.
    The timeline owns its own state machine, so a transition is logged once and
    only when the state actually flips.
    """
    kind = (
        await session.execute(
            sa.select(Event.kind)
            .where(Event.page_url == page_url, Event.kind.in_(_LIVENESS_KINDS))
            .order_by(Event.occurred_at.desc(), Event.id.desc())
            .limit(1)
        )
    ).scalars().first()
    return kind in (PAGE_UNREACHABLE, PAGE_DEAD)


def record(
    session,
    kind: str,
    *,
    page_url: str | None = None,
    hostname: str | None = None,
    summary: str,
    detail: str | None = None,
) -> Event:
    """Stage an event on ``session``. The caller owns the commit.

    Not committed here on purpose: an event describing a change must land in the
    same transaction as the change, so the two cannot diverge.
    """
    event = Event(
        kind=kind,
        page_url=page_url,
        hostname=hostname,
        summary=summary[:512],
        detail=detail,
    )
    session.add(event)
    return event


async def backfill(db: Database) -> dict:
    """Reconstruct what the timeline can prove from already-stored page state.

    A corpus crawled before the timeline existed still contains real history:
    when each page was first seen, when its content last changed, and when a
    service was last successfully fetched before it stopped answering. Without
    this the feature is blind to everything collected so far — including, on the
    corpus this was built against, 34 services already known to be dead.

    Timestamps are *when we observed* a transition, not when it truly happened;
    a service that went dark the day after its last fetch is indistinguishable
    from one that went dark an hour before the next attempt. Reconstructed events
    are marked as such in ``detail`` so nobody mistakes them for live detections.

    Idempotent — re-running adds nothing, so it is safe to call on every upgrade.
    """
    marker = "reconstructed from stored page state"
    async with db.session() as session:
        existing = set(
            (
                await session.execute(
                    sa.select(Event.page_url, Event.kind).where(Event.detail == marker)
                )
            ).all()
        )
        pages = (
            await session.execute(
                sa.select(
                    Page.url, Page.hostname, Page.title, Page.status,
                    Page.content_sha256, Page.created_at, Page.fetched_at,
                ).where(Page.status.in_(("crawled", "dead")))
            )
        ).all()

        added = 0
        for url, host, title, status, sha, created_at, fetched_at in pages:
            if sha and (url, PAGE_NEW) not in existing:
                event = record(
                    session, PAGE_NEW, page_url=url, hostname=host,
                    summary=f"First seen: {title or url}", detail=marker,
                )
                event.occurred_at = created_at
                added += 1
            if status == "dead" and (url, PAGE_DEAD) not in existing:
                # Distinguish "went dark" from "never answered at all" — very
                # different intelligence, and the stored content says which.
                kind = PAGE_UNREACHABLE if sha else PAGE_DEAD
                if (url, kind) in existing:
                    continue
                event = record(
                    session, kind, page_url=url, hostname=host,
                    summary=(
                        f"Stopped responding: {title or url}" if sha
                        else f"Never answered: {url}"
                    ),
                    detail=marker,
                )
                event.occurred_at = fetched_at or created_at
                added += 1
        await session.commit()

    log.info("backfilled %d event(s) from stored page state", added)
    return {"events": added}


async def list_events(
    db: Database,
    *,
    kind: str | None = None,
    host: str | None = None,
    notable_only: bool = False,
    limit: int = 100,
) -> list[dict]:
    """Most recent events first."""
    stmt = sa.select(Event).order_by(Event.occurred_at.desc(), Event.id.desc())
    if kind:
        stmt = stmt.where(Event.kind == kind)
    if notable_only:
        stmt = stmt.where(Event.kind.in_(NOTABLE))
    if host:
        stmt = stmt.where(Event.hostname == host)
    async with db.session() as session:
        rows = (await session.execute(stmt.limit(limit))).scalars().all()
    return [
        {
            "id": e.id,
            "at": e.occurred_at.isoformat() if e.occurred_at else None,
            "kind": e.kind,
            "label": label(e.kind),
            "host": e.hostname,
            "page_url": e.page_url,
            "summary": e.summary,
            "detail": e.detail,
        }
        for e in rows
    ]


async def host_liveness(db: Database, limit: int = 200) -> list[dict]:
    """Per-service uptime view: who is answering, who went dark, and when.

    A hidden service disappearing is the single most actionable signal here —
    exit scam, seizure, or infrastructure rotation — and it is invisible in any
    view that only shows what was successfully fetched.
    """
    async with db.session() as session:
        rows = (
            await session.execute(
                sa.select(
                    Page.hostname,
                    sa.func.count().label("known"),
                    # "crawled" alone does not mean answering: a previously good
                    # page that stops responding deliberately keeps its status so
                    # its archived content survives, and only its failure count
                    # rises. Counting it as live hid every outage — a service
                    # that went dark still showed as up.
                    sa.func.sum(sa.case(
                        (sa.and_(Page.status == "crawled",
                                 sa.func.coalesce(Page.consecutive_failures, 0) == 0), 1),
                        else_=0,
                    )).label("live"),
                    sa.func.sum(sa.case(
                        (sa.and_(Page.status == "crawled",
                                 sa.func.coalesce(Page.consecutive_failures, 0) > 0), 1),
                        else_=0,
                    )).label("failing"),
                    sa.func.sum(sa.case((Page.status == "dead", 1), else_=0)).label("dead"),
                    sa.func.sum(
                        sa.case((Page.content_sha256.isnot(None), 1), else_=0)
                    ).label("answered"),
                    sa.func.max(Page.fetched_at).label("last_fetch"),
                    sa.func.max(Page.content_changed_at).label("last_change"),
                )
                .where(Page.hostname.isnot(None))
                .group_by(Page.hostname)
            )
        ).all()

        # When did each host last go quiet? Taken from the event log rather than
        # recomputed, so the timeline and this view can never tell different
        # stories about the same outage.
        offline_rows = (
            await session.execute(
                sa.select(Event.hostname, sa.func.max(Event.occurred_at))
                .where(Event.kind.in_((PAGE_UNREACHABLE, PAGE_DEAD)))
                .group_by(Event.hostname)
            )
        ).all()
    offline_at = {h: t for h, t in offline_rows if h}

    out = []
    for host, known, live, failing, dead, answered, last_fetch, last_change in rows:
        live, failing = int(live or 0), int(failing or 0)
        dead, answered = int(dead or 0), int(answered or 0)
        if live:
            state = "up"
        elif failing or (dead and answered):
            state = "down"      # was reachable, isn't now: the actionable one
        elif dead:
            state = "never"     # never answered on any attempt: noise, not an outage
        else:
            state = "unknown"   # only ever queued, never actually fetched
        out.append(
            {
                "host": host,
                "state": state,
                "known": known,
                "live": live,
                "failing": failing,
                "dead": dead,
                "last_fetch": last_fetch.isoformat() if last_fetch else None,
                "last_change": last_change.isoformat() if last_change else None,
                "offline_since": (
                    offline_at[host].isoformat()
                    if state == "down" and host in offline_at and offline_at[host]
                    else None
                ),
            }
        )
    order = {"down": 0, "up": 1, "never": 2, "unknown": 3}
    out.sort(key=lambda h: (order[h["state"]], -h["known"]))
    return out[:limit]
