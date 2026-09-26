"""Phrase/exclusion search. SQLite FTS5 is maintained by database triggers."""

import datetime as dt
import shlex

import sqlalchemy as sa

from .models import Ioc, Page


def search_terms(q):
    terms = shlex.split(q)
    if len(terms) > 30:
        raise ValueError("Use at most 30 terms")
    positive = [t for t in terms if not t.startswith("-")]
    negative = [t[1:] for t in terms if t.startswith("-") and len(t) > 1]
    return positive, negative


async def search_pages(db, *, q="", host="", kind="", since=None, until=None, limit=30, offset=0):
    positive, negative = search_terms(q)
    clauses = [Page.blocked.is_(False), Page.content.is_not(None)]
    full = sa.func.coalesce(Page.title, "") + " " + sa.func.coalesce(Page.content, "")
    if db._engine.dialect.name == "sqlite" and positive:

        def phrase(v):
            return '"' + v.replace('"', '""') + '"'

        match = " AND ".join(phrase(t) for t in positive)
        for t in negative:
            match += " NOT " + phrase(t)
        clauses.append(
            Page.url.in_(
                sa.select(sa.column("url"))
                .select_from(sa.table("pages_fts"))
                .where(sa.text("pages_fts MATCH :fts_query"))
                .params(fts_query=match)
            )
        )
    else:
        clauses.extend(full.icontains(t, autoescape=True) for t in positive)
        clauses.extend(~full.icontains(t, autoescape=True) for t in negative)
    if host:
        clauses.append(Page.hostname == host.lower())
    if kind:
        clauses.append(Page.url.in_(sa.select(Ioc.page_url).where(Ioc.ioc_type == kind)))
    if since:
        clauses.append(Page.content_captured_at >= dt.datetime.combine(since, dt.time.min))
    if until:
        clauses.append(
            Page.content_captured_at
            < dt.datetime.combine(until + dt.timedelta(days=1), dt.time.min)
        )
    if since and until and since > until:
        raise ValueError("Start date must precede end date")
    async with db.session() as s:
        total = await s.scalar(sa.select(sa.func.count()).select_from(Page).where(*clauses))
        # Load only one bounded result page; never binary bodies or all vectors.
        rows = (
            await s.execute(
                sa.select(
                    Page.url,
                    Page.title,
                    Page.content,
                    Page.content_captured_at,
                    Page.content_sha256,
                )
                .where(*clauses)
                .order_by(Page.content_captured_at.desc(), Page.url)
                .offset(offset)
                .limit(limit)
            )
        ).all()
    results = []
    for r in rows:
        content = r.content or ""
        positions = [content.lower().find(t.lower()) for t in positive]
        start = max(0, min((p for p in positions if p >= 0), default=0) - 90)
        results.append(
            {
                "url": r.url,
                "title": r.title,
                "captured_at": r.content_captured_at,
                "snippet": content[start : start + 600],
                "sha256": r.content_sha256,
            }
        )
    return {
        "results": results,
        "total": total,
        "offset": offset,
        "limit": limit,
        "highlight_terms": positive,
        "engine": "fts5" if db._engine.dialect.name == "sqlite" else "literal-text",
    }
