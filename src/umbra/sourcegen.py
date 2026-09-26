"""Generate source packs from a crawl's own evidence.

Curated seed lists are the hard part of a dark-web product and they cannot be
invented — an address that is guessed rather than observed is either dead or
belongs to someone unrelated, and shipping either is worse than shipping nothing.

What *can* be done honestly is promote what a crawl has already proven: a host
that answered, and produced listings or actor identifiers, has earned a place in
a pack, and the record of why it earned it travels with it. That turns a corpus
into reusable coverage, and it means a customer's second deployment starts from
what their first one learned instead of from a wiki.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
from pathlib import Path

import sqlalchemy as sa

from .db import Database
from .logging import get_logger
from .models import STATUS_CRAWLED, Ioc, Listing, Page

log = get_logger("sourcegen")

_ACTOR_TYPES = ("btc", "eth", "xmr", "pgp_fp", "contact_email", "jabber", "handle")

_LOCAL_NAMES = ("localhost", "localhost.localdomain")


def is_publishable(host: str) -> bool:
    """Whether a host is safe to put in a pack that will be shipped to someone else.

    Local fixtures and dev servers end up in a working database — a mock site on
    ``127.0.0.1`` used during testing is indistinguishable from a real host once
    it has been crawled. Promoting one into a pack ships a seed list that tells
    the customer to crawl their own loopback interface: it finds nothing, or
    worse, finds something of theirs and files it as dark-web intelligence.

    Found in exactly this way — a generated pack contained ``http://127.0.0.1/``
    from four demo pages left in a live corpus.
    """
    if not host:
        return False
    name = host.strip().lower()
    # Strip the port without mangling IPv6, whose address is itself full of
    # colons: "[::1]:8000" is bracketed, "::1" is bare, "host:8000" has exactly
    # one. Splitting on the first colon unconditionally turns "::1" into "",
    # which then parses as no address at all and reads as publishable.
    if name.startswith("["):
        name = name[1:].partition("]")[0]
    elif name.count(":") == 1:
        name = name.split(":", 1)[0]
    if not name:
        return False
    if name in _LOCAL_NAMES or name.endswith((".local", ".localhost", ".internal", ".test")):
        return False
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return True  # a hostname, not a literal address
    return not (
        address.is_loopback or address.is_private or address.is_link_local
        or address.is_reserved or address.is_multicast or address.is_unspecified
    )


async def _host_stats(db: Database) -> dict[str, dict]:
    async with db.session() as session:
        rows = (
            await session.execute(
                sa.select(
                    Page.hostname,
                    sa.func.count().label("pages"),
                    sa.func.max(Page.fetched_at).label("last_seen"),
                    sa.func.min(Page.url).label("any_url"),
                )
                .where(Page.status == STATUS_CRAWLED, Page.hostname.isnot(None))
                .group_by(Page.hostname)
            )
        ).all()
        listings = dict(
            (
                await session.execute(
                    sa.select(Page.hostname, sa.func.count())
                    .select_from(Listing)
                    .join(Page, Page.url == Listing.page_url)
                    .group_by(Page.hostname)
                )
            ).all()
        )
        identifiers = dict(
            (
                await session.execute(
                    sa.select(Page.hostname, sa.func.count())
                    .select_from(Ioc)
                    .join(Page, Page.url == Ioc.page_url)
                    .where(Ioc.ioc_type.in_(_ACTOR_TYPES))
                    .group_by(Page.hostname)
                )
            ).all()
        )
        titles = dict(
            (
                await session.execute(
                    sa.select(Page.hostname, sa.func.min(Page.title))
                    .where(Page.title.isnot(None), Page.status == STATUS_CRAWLED)
                    .group_by(Page.hostname)
                )
            ).all()
        )

    return {
        host: {
            "pages": pages,
            "last_seen": last_seen,
            "root": f"http://{host}/",
            "listings": int(listings.get(host, 0)),
            "identifiers": int(identifiers.get(host, 0)),
            "title": (titles.get(host) or "").strip()[:80],
        }
        for host, pages, last_seen, _any_url in rows
    }


def _pack(name: str, description: str, category: str, hosts: list[tuple[str, dict, str]]) -> dict:
    today = dt.date.today().isoformat()
    return {
        "name": name,
        "description": description,
        "category": category,
        "version": today,
        "generated_from": "observed crawl results — every host below answered at least once",
        "sources": [
            {
                "url": stats["root"],
                "note": stats["title"],
                "last_seen": (
                    stats["last_seen"].date().isoformat()
                    if hasattr(stats["last_seen"], "date") else str(stats["last_seen"])[:10]
                ),
                "evidence": evidence,
            }
            for _host, stats, evidence in hosts
        ],
    }


async def generate(db: Database, out_dir: str | Path, min_pages: int = 1) -> dict:
    """Write packs derived from what this database has actually observed."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stats = await _host_stats(db)

    dropped = [h for h in stats if not is_publishable(h)]
    if dropped:
        log.info("excluded %d non-routable host(s) from packs: %s", len(dropped), dropped[:5])
    stats = {h: s for h, s in stats.items() if is_publishable(h)}

    marketplaces = sorted(
        ((h, s, f"{s['listings']} listing(s) extracted") for h, s in stats.items() if s["listings"] >= 3),
        key=lambda x: -x[1]["listings"],
    )
    actors = sorted(
        (
            (h, s, f"{s['identifiers']} actor identifier(s) extracted")
            for h, s in stats.items()
            if s["identifiers"] >= 2 and s["listings"] < 3
        ),
        key=lambda x: -x[1]["identifiers"],
    )
    live = sorted(
        ((h, s, f"{s['pages']} page(s) fetched successfully") for h, s in stats.items() if s["pages"] >= min_pages),
        key=lambda x: -x[1]["pages"],
    )

    packs = {
        # Named for what the evidence supports, not what would sell better. The
        # extractor detects *priced listings*, which a criminal market and a
        # legitimate hosting provider's pricing page produce identically — the
        # top entries generated from a real corpus were a server host and a
        # blockchain explorer, above an actual drugs market. Calling this
        # "marketplaces" would put a claim in the product that the data cannot
        # support, and an operator would find out the hard way.
        "commerce": _pack(
            "commerce",
            "Hosts where priced listings were extracted. High signal density, but "
            "this means 'sells something', not 'sells something illegal' — "
            "legitimate services with pricing pages appear here too. Review the "
            "notes and prune before using as a targeting list.",
            "commerce",
            marketplaces,
        ),
        "actor-infrastructure": _pack(
            "actor-infrastructure",
            "Hosts carrying wallets, PGP keys or published contact addresses without "
            "being marketplaces — forums, vendor pages and profiles worth revisiting.",
            "actors",
            actors,
        ),
        "verified-live": _pack(
            "verified-live",
            "Every hidden service observed answering. Broad coverage baseline; expect "
            "lower signal density than the targeted packs.",
            "general",
            live,
        ),
    }

    written = {}
    for name, pack in packs.items():
        path = out / f"{name}.json"
        path.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
        written[name] = len(pack["sources"])
    log.info("generated source packs: %s", written)
    return written
