"""Quality denominators describe retained captures, independent of frontier status."""
import datetime as dt

import sqlalchemy as sa

from .models import Page, utcnow


async def quality(db):
    async with db.session() as s:
        kept = [Page.blocked.is_(False), Page.content.is_not(None)]
        complete = [*kept, Page.body_truncated.is_(False), Page.content_sha256.is_not(None)]
        async def count(*conditions):
            return await s.scalar(sa.select(sa.func.count()).select_from(Page).where(*conditions))
        retained = await count(*kept)
        bodies = await count(*complete)
        unique = await s.scalar(sa.select(sa.func.count(sa.distinct(Page.content_sha256)))
                                .where(*complete))
        # Useful is deliberately an observable proxy, not an intelligence verdict.
        useful = await s.scalar(sa.select(sa.func.count(sa.distinct(Page.content_sha256)))
                               .where(*complete, sa.func.length(sa.func.trim(Page.content)) >= 80))
        fresh = await count(*kept, Page.content_captured_at >= utcnow()-dt.timedelta(days=7))
        unknown = await count(*kept, Page.content_captured_at.is_(None))
        errors = await count(*kept, Page.extraction_errors.is_not(None),
                             Page.extraction_errors != "[]")
        return {
            "retained_pages": retained, "complete_captures": bodies,
            "unique_complete_bodies": unique, "unique_substantive_pages": useful,
            "duplicate_pages": bodies-unique,
            "duplicate_rate": round((bodies-unique)/bodies, 4) if bodies else None,
            "fresh_within_7_days": fresh, "older_than_7_days": retained-fresh-unknown,
            "capture_date_unknown": unknown, "pages_with_extraction_errors": errors,
            "extraction_status_unknown": await count(*kept, Page.extraction_errors.is_(None)),
            "truncated_or_unknown": retained-bodies,
            "definition": "Substantive means at least 80 extracted characters in a complete capture; analyst relevance is not inferred.",
        }
