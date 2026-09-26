"""Version retention and readable comparisons. No invented historical captures."""
import difflib

import sqlalchemy as sa

from .models import CaseItem, ExtractionFeedback, Page, PageVersion


def snapshot(page: Page, *, legacy: bool = False) -> PageVersion:
    captured_at = page.content_captured_at or (None if legacy else page.fetched_at)
    return PageVersion(
        page_url=page.url, captured_at=captured_at, title=page.title,
        content=page.content, raw_body=page.raw_body, capture_metadata=page.capture_metadata,
        body_sha256=page.content_sha256, body_truncated=page.body_truncated,
        final_url=page.final_url, http_status=page.http_status, legacy=legacy,
    )


async def retain_version(session, page: Page, limit: int) -> None:
    session.add(snapshot(page))
    await session.flush()
    # Saved case exhibits remain until explicit page retention/policy removal.
    keep = sa.select(PageVersion.id).where(PageVersion.page_url == page.url).order_by(
        PageVersion.id.desc()
    ).limit(limit)
    await session.execute(sa.delete(PageVersion).where(
        PageVersion.page_url == page.url, PageVersion.id.not_in(keep),
        PageVersion.id.not_in(sa.select(CaseItem.version_id)),
        PageVersion.id.not_in(sa.select(ExtractionFeedback.version_id)),
    ))


def describe(version: PageVersion) -> dict:
    return {
        "id": version.id, "page_url": version.page_url, "title": version.title,
        "captured_at": version.captured_at, "body_sha256": version.body_sha256,
        "body_retained": (version.__dict__["raw_body"] is not None
                          if "raw_body" in version.__dict__ else version.body_available),
        "truncated": version.body_truncated, "legacy": version.legacy,
    }


def compare(before: PageVersion, after: PageVersion) -> dict:
    if before.page_url != after.page_url:
        raise ValueError("Choose versions of the same page")
    # Bound the display; stored captures remain intact.
    left, right = (before.content or "")[:100_000], (after.content or "")[:100_000]
    lines = list(difflib.unified_diff(
        left.splitlines(), right.splitlines(), fromfile=f"version {before.id}",
        tofile=f"version {after.id}", lineterm="",
    ))
    diff = "\n".join(lines)
    return {"before": describe(before), "after": describe(after), "diff": diff[:200_000],
            "display_truncated": len(diff) > 200_000 or any(
                len(v.content or "") > 100_000 for v in (before, after)
            )}
