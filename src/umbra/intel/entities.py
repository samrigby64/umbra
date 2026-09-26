"""Entity resolution — cluster identifiers into threat actors.

A threat actor reuses identifiers: the same crypto wallet, email, or handle
appears across their pages. This pass builds a co-occurrence graph over "strong"
identifiers (crypto addresses, emails, handles) and takes connected components as
actors, so an analyst can pivot from one indicator to everything linked to it.

It runs as a batch over the accumulated IOC table (``umbra resolve-actors``) —
cheap, deterministic, and re-runnable.

Aggregator pages (marketplace indexes listing many vendors' wallets) would merge
unrelated actors, so pages with more than ``max_identifiers_per_page`` distinct
identifiers are not used to link — only to count reach.
"""

from __future__ import annotations

from collections import defaultdict

import sqlalchemy as sa

from ..db import Database
from ..logging import get_logger
from ..models import Actor, ActorIdentifier, Ioc, RelationshipReview

log = get_logger("entities")

# Identifiers that genuinely belong to an *actor*. Crypto-address reuse is the
# canonical dark-web actor-linking signal. A PGP fingerprint is stronger still:
# wallets get burned and onion addresses rotate after every takedown, but the key
# survives, because the operator's reputation is signed with it.
#
# ``email`` is deliberately absent — breach dumps are full of victim addresses,
# which would cluster unrelated victims into fake actors. ``contact_email`` and
# ``jabber`` are the addresses an operator *published so buyers could reach them*
# (see ``enrich/ioc.py``), which is the opposite kind of fact, so those do link.
STRONG_TYPES = ("btc", "eth", "xmr", "handle", "pgp_fp", "contact_email", "jabber")


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict = {}

    def add(self, x) -> None:
        self.parent.setdefault(x, x)

    def find(self, x):
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


async def resolve_actors(db: Database, max_identifiers_per_page: int = 8) -> dict:
    """Rebuild the actor graph from the IOC table. Returns summary counts."""
    async with db.session() as session:
        rows = (
            await session.execute(
                sa.select(Ioc.page_url, Ioc.ioc_type, Ioc.value).where(
                    Ioc.ioc_type.in_(STRONG_TYPES)
                )
            )
        ).all()
        reviews = (await session.execute(sa.select(RelationshipReview))).scalars().all()

    page_idents: dict[str, list] = defaultdict(list)
    ident_pages: dict[tuple, set] = defaultdict(set)
    uf = _UnionFind()
    for url, ioc_type, value in rows:
        ident = (ioc_type, value)
        uf.add(ident)
        page_idents[url].append(ident)
        ident_pages[ident].add(url)

    rejected = [((r.left_type, r.left_value), (r.right_type, r.right_value))
                for r in reviews if r.verdict == "rejected"]

    def safe_union(left, right):
        a, b = uf.find(left), uf.find(right)
        for x, y in rejected:
            if x in uf.parent and y in uf.parent and {
                uf.find(x), uf.find(y)
            } == {a, b}:
                return
        uf.union(left, right)

    for url, idents in sorted(page_idents.items()):
        distinct = sorted(set(idents))
        if len(distinct) > max_identifiers_per_page:
            continue  # aggregator page — don't link, avoids merging unrelated actors
        for other in distinct[1:]:
            safe_union(distinct[0], other)

    components: dict[tuple, list] = defaultdict(list)
    for ident in uf.parent:
        components[uf.find(ident)].append(ident)

    async with db.session() as session:
        await session.execute(sa.delete(ActorIdentifier))
        await session.execute(sa.delete(Actor))

        n_actors = 0
        for idents in components.values():
            pages: set[str] = set()
            for ident in idents:
                pages |= ident_pages[ident]
            # A single identifier on a single page isn't an "actor" worth surfacing.
            if len(idents) < 2 and len(pages) < 2:
                continue
            first_type, first_value = idents[0]
            actor = Actor(label=f"{first_type}:{first_value[:64]}", page_count=len(pages))
            session.add(actor)
            await session.flush()  # assign actor.id
            for ioc_type, value in idents:
                session.add(ActorIdentifier(actor_id=actor.id, ioc_type=ioc_type, value=value))
            n_actors += 1
        await session.commit()

    summary = {"actors": n_actors, "identifiers": len(uf.parent)}
    log.info("resolved %d actors from %d identifiers", summary["actors"], summary["identifiers"])
    return summary
