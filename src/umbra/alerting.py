"""Watchlist evaluation and alert dispatch.

A watchlist is a saved question. Two kinds of question, and the difference is
what makes this useful to more than one sort of customer:

* **Content** — "does my brand / this email / this wallet appear anywhere?"
  Answered against the corpus as it stands. One page matching is one fact.
* **Event** — "tell me when something *changes*": a marketplace stops answering,
  a vendor's PGP key rotates, a page's contents move. Answered against the
  timeline, and repeatable — a service that goes down, recovers, and goes down
  again is three separate things worth knowing.

The second kind is what turns the timeline from a screen someone has to remember
to open into something that reaches them. Both funnel into the same
:class:`Alert` table and the same webhook dispatch, so a customer configures one
mechanism regardless of which question they are asking.
"""

from __future__ import annotations

import httpx
import sqlalchemy as sa

from .db import Database
from .logging import get_logger
from .models import Alert, Credential, Event, Ioc, Page, PageVersion, Watchlist
from .netguard import UnsafeDestination, guard_request
from .timeline import NOTABLE

log = get_logger("alerting")

CONTENT_KINDS = ("keyword", "domain", "email", "ioc")
EVENT_KIND = "event"
KINDS = (*CONTENT_KINDS, EVENT_KIND)

# ``event`` watchlist values: an event kind, or "notable" for the curated set of
# things worth waking someone for. Optionally scoped to one service with
# "<kind>@<hostname>" — a customer watching one marketplace does not want every
# outage on the dark web.
NOTABLE_ALIAS = "notable"


def parse_event_value(value: str) -> tuple[str, str | None]:
    """``"page_unreachable@x.onion"`` -> ``("page_unreachable", "x.onion")``."""
    kind, _, host = value.partition("@")
    return kind.strip() or NOTABLE_ALIAS, (host.strip() or None)


async def _match_pages(session, watchlist: Watchlist) -> set[str]:
    value = watchlist.value
    if watchlist.kind == "keyword":
        stmt = sa.select(Page.url).where(
            sa.or_(
                Page.content.contains(value),
                Page.title.contains(value),
                Page.summary.contains(value),
            )
        )
    elif watchlist.kind == "domain":
        stmt = sa.select(Page.url).where(Page.hostname == value)
    elif watchlist.kind == "email":
        stmt = sa.select(Credential.page_url).where(Credential.email == value.lower())
    elif watchlist.kind == "ioc":
        stmt = sa.select(Ioc.page_url).where(Ioc.value == value)
    else:
        return set()
    return set((await session.execute(stmt)).scalars())


async def _match_events(session, watchlist: Watchlist) -> list[Event]:
    kind, host = parse_event_value(watchlist.value)
    stmt = sa.select(Event)
    if kind == NOTABLE_ALIAS:
        stmt = stmt.where(Event.kind.in_(NOTABLE))
    else:
        stmt = stmt.where(Event.kind == kind)
    if host:
        stmt = stmt.where(Event.hostname == host)
    # Newest first, bounded: an event watchlist added to a corpus with months of
    # history should not fire thousands of alerts about things that happened
    # before anyone was watching.
    stmt = stmt.order_by(Event.occurred_at.desc(), Event.id.desc()).limit(500)
    events = list((await session.execute(stmt)).scalars())
    filtered = []
    for event in events:
        if event.kind == 'page_changed' and event.page_url:
            # Navigation/script churn often changes the body hash without changing
            # extracted text. Preserve the event but avoid an unhelpful alert.
            versions = (await session.execute(sa.select(PageVersion.content).where(
                PageVersion.page_url == event.page_url, PageVersion.captured_at <= event.occurred_at
            ).order_by(PageVersion.id.desc()).limit(2))).scalars().all()
            if len(versions) == 2 and versions[0] is not None and versions[1] is not None:
                if ' '.join(versions[0].split()) == ' '.join(versions[1].split()):
                    continue
        filtered.append(event)
    return filtered


async def evaluate_watchlists(db: Database) -> dict:
    """Match all active watchlists, record new alerts, dispatch webhooks."""
    new_alerts = 0
    async with db.write_session() as session:
        watchlists = (
            await session.execute(sa.select(Watchlist).where(Watchlist.active.is_(True)))
        ).scalars().all()

        for watchlist in watchlists:
            pending: list[Alert] = []
            if watchlist.kind == EVENT_KIND:
                for event in await _match_events(session, watchlist):
                    pending.append(
                        Alert(
                            watchlist_id=watchlist.id,
                            page_url=event.page_url or "",
                            matched_value=event.summary[:512],
                            dedup_key=f"event:{event.id}",
                            event_id=event.id,
                        )
                    )
            else:
                # Exact body duplicates share one alert, while page/IOC observations
                # remain independently preserved. Incomplete bodies are never merged.
                matched = await _match_pages(session, watchlist)
                seen_bodies = set()
                prior_urls = set((await session.scalars(sa.select(Alert.page_url).where(Alert.watchlist_id == watchlist.id))).all())
                if prior_urls:
                    seen_bodies.update((await session.scalars(sa.select(Page.content_sha256).where(
                        Page.url.in_(prior_urls), Page.body_truncated.is_(False), Page.content_sha256.is_not(None)))).all())
                for url in sorted(matched):
                    body = (await session.execute(sa.select(Page.content_sha256, Page.body_truncated).where(Page.url == url))).first()
                    digest = body[0] if body and body[1] is False else None
                    if digest and digest in seen_bodies:
                        continue
                    if digest:
                        seen_bodies.add(digest)
                    pending.append(
                        Alert(
                            watchlist_id=watchlist.id,
                            page_url=url,
                            matched_value=watchlist.value,
                            dedup_key=url,
                        )
                    )

            if not pending:
                continue
            known = set(
                (
                    await session.execute(
                        sa.select(Alert.dedup_key).where(
                            Alert.watchlist_id == watchlist.id,
                            Alert.dedup_key.in_([a.dedup_key for a in pending]),
                        )
                    )
                ).scalars()
            )
            for alert in pending:
                if alert.dedup_key in known:
                    continue
                session.add(alert)
                new_alerts += 1
        await session.commit()

    delivered = await _dispatch(db)
    if new_alerts or delivered:
        log.info("watchlists: %d new alert(s), %d delivered", new_alerts, delivered)
    return {"new_alerts": new_alerts, "delivered": delivered}


async def _dispatch(db: Database) -> int:
    async with db.session() as session:
        rows = (
            await session.execute(
                sa.select(Alert, Watchlist).join(
                    Watchlist, Alert.watchlist_id == Watchlist.id
                ).where(Alert.delivered.is_(False))
            )
        ).all()
        events = {}
        event_ids = [a.event_id for a, _ in rows if a.event_id]
        if event_ids:
            events = {
                e.id: e
                for e in (
                    await session.execute(sa.select(Event).where(Event.id.in_(event_ids)))
                ).scalars()
            }

        to_mark: list[int] = []
        posts: list[tuple[int, str, dict]] = []
        for alert, watchlist in rows:
            if watchlist.webhook_url:
                payload = {
                    "watchlist": watchlist.name,
                    "kind": watchlist.kind,
                    "value": watchlist.value,
                    "page_url": alert.page_url,
                    "matched_value": alert.matched_value,
                }
                event = events.get(alert.event_id) if alert.event_id else None
                if event is not None:
                    # The receiving system should not have to call back to find
                    # out what happened — an alert that says only "something
                    # changed" costs the customer a round trip to act on.
                    payload["event"] = {
                        "id": event.id,
                        "kind": event.kind,
                        "host": event.hostname,
                        "summary": event.summary,
                        "detail": event.detail,
                        "occurred_at": (
                            event.occurred_at.isoformat() if event.occurred_at else None
                        ),
                    }
                posts.append((alert.id, watchlist.webhook_url, payload))
            else:
                to_mark.append(alert.id)  # recorded-only watchlist (queryable via API)

    delivered = 0
    if posts:
        # Webhooks go to clearnet customer endpoints — no Tor proxy, which is
        # exactly why they need the destination guard: nothing else stops a
        # webhook from pointing at this host's own network, and the body is
        # collected intelligence. Checked again here, not only at creation,
        # because the URL's DNS can change after the watchlist was saved.
        async with httpx.AsyncClient(
            timeout=10.0, event_hooks={"request": [guard_request]}
        ) as client:
            for alert_id, url, payload in posts:
                try:
                    resp = await client.post(url, json=payload)
                    ok = resp.status_code < 400
                except UnsafeDestination as exc:
                    ok = False
                    log.warning("webhook for alert %d refused: %s", alert_id, exc)
                except Exception:
                    ok = False
                if ok:
                    to_mark.append(alert_id)
                    delivered += 1
                else:
                    log.warning("webhook delivery failed for alert %d", alert_id)

    if to_mark:
        async with db.session() as session:
            await session.execute(
                sa.update(Alert).where(Alert.id.in_(to_mark)).values(delivered=True)
            )
            await session.commit()
    return delivered
