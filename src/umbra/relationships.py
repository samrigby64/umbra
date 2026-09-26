"""Explainable co-occurrence links and persistent human review decisions."""
import hashlib
import itertools
import json
from collections import defaultdict

import sqlalchemy as sa

from .models import Ioc, RelationshipReview


def pair_key(left: tuple[str, str], right: tuple[str, str]) -> str:
    return hashlib.sha256(json.dumps(sorted([left, right]), separators=(",", ":")).encode()).hexdigest()


async def relationship_rows(db, *, limit=100, offset=0):
    from .intel.entities import STRONG_TYPES

    async with db.session() as session:
        records = (await session.execute(sa.select(Ioc).where(
            Ioc.ioc_type.in_(STRONG_TYPES)
        ).order_by(Ioc.page_url, Ioc.ioc_type, Ioc.value))).scalars().all()
        reviews = {r.pair_key: r for r in (await session.execute(
            sa.select(RelationshipReview)
        )).scalars()}
    pages = defaultdict(dict)
    for record in records:
        pages[record.page_url][(record.ioc_type, record.value)] = record.context
    edges = {}
    for url, identifiers in pages.items():
        if len(identifiers) > 8:
            continue
        for left, right in itertools.combinations(sorted(identifiers), 2):
            key = pair_key(left, right)
            entry = edges.setdefault(key, {"key": key, "left": left, "right": right,
                                          "sources": [], "source_count": 0})
            entry["source_count"] += 1
            if len(entry["sources"]) < 10:
                entry["sources"].append({"url": url, "left_context": identifiers[left],
                                         "right_context": identifiers[right]})
    # Keep reviewed links visible even if the source disappeared or was reprocessed.
    for key, review in reviews.items():
        edges.setdefault(key, {"key": key, "left": [review.left_type, review.left_value],
                               "right": [review.right_type, review.right_value],
                               "sources": [], "source_count": 0})
    ordered = sorted(edges.values(), key=lambda e: (-e["source_count"], e["key"]))
    for edge in ordered:
        review = reviews.get(edge["key"])
        edge.update(verdict=review.verdict if review else "inferred",
                    reason=review.reason if review else "Identifiers co-occur on a page",
                    reviewer=review.reviewer if review else None,
                    reviewed_at=review.reviewed_at if review else None)
    return {"relationships": ordered[offset:offset + limit], "total": len(ordered),
            "offset": offset, "limit": limit,
            "notice": "Co-occurrence does not establish shared ownership or personal identity."}
