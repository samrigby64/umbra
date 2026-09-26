"""Case workspaces, capture comparisons and reviewed links (shared team access)."""
import hashlib
import json
from typing import Literal

import sqlalchemy as sa
from fastapi import Header, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ..access import principal, case_access, audit
from ..models import CaseMember
from ..evidence import build_bundle
from ..models import (
    CaseActivity, CaseItem, Investigation, Page, PageVersion, RelationshipReview, utcnow,
)
from ..relationships import pair_key, relationship_rows
from ..versions import compare, describe, snapshot


class CaseInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    assigned_to: str = Field(default="", max_length=255)
    notes: str = Field(default="", max_length=20_000)
    tags: str = Field(default="", max_length=1000)
    status: Literal["open", "closed"] = "open"


class ItemInput(BaseModel):
    version_id: int = Field(gt=0)
    notes: str = Field(default="", max_length=20_000)
    tags: str = Field(default="", max_length=1000)
    verdict: Literal["unreviewed", "relevant", "irrelevant", "needs_followup"] = "unreviewed"


class ReviewInput(BaseModel):
    left: tuple[str, str]
    right: tuple[str, str]
    verdict: Literal["inferred", "confirmed", "rejected"]
    reason: str = Field(min_length=3, max_length=4000)


def plain(row):
    return {c.name: getattr(row, c.name) for c in row.__table__.columns}


def register(app, db, settings, auth, admin):
    async def actor(key):
        return (await principal(db, key))["actor"]

    async def require_case(s, case_id, who, write=False):
        row = await s.get(Investigation, case_id)
        if row is None:
            raise HTTPException(404, "Case not found")
        await case_access(s, case_id, who, write)
        return row

    @app.get("/versions", dependencies=auth)
    async def versions(url: str, limit: int = Query(50, ge=1, le=500)):
        async with db.session() as s:
            rows = (await s.execute(sa.select(PageVersion).where(
                PageVersion.page_url == url
            ).options(sa.orm.defer(PageVersion.raw_body), sa.orm.defer(PageVersion.content))
                .order_by(PageVersion.id.desc()).limit(limit))).scalars().all()
        return {"versions": [describe(v) for v in rows]}

    @app.post("/versions/capture-stored", dependencies=admin)
    async def capture_stored(payload: dict):
        async with db.write_session() as s:
            page = await s.get(Page, payload.get("url", ""))
            if page is None or page.blocked or not page.content:
                raise HTTPException(404, "No retained page text")
            version = (await s.execute(sa.select(PageVersion).where(
                PageVersion.page_url == page.url,
                PageVersion.body_sha256 == page.content_sha256,
            ).order_by(PageVersion.id.desc()).limit(1))).scalar_one_or_none()
            if version is None:
                version = snapshot(page, legacy=True)
                s.add(version)
                await s.commit()
            return describe(version)

    @app.get("/versions/compare", dependencies=auth)
    async def compare_versions(before: int, after: int):
        async with db.session() as s:
            left, right = await s.get(PageVersion, before), await s.get(PageVersion, after)
            if left is None or right is None:
                raise HTTPException(404, "Version unavailable (possibly removed by retention)")
            if left.page_url != right.page_url:
                raise HTTPException(400, "Choose two versions of the same page")
        return compare(left, right)

    @app.get("/cases", dependencies=auth)
    async def cases(x_api_key: str | None = Header(None), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        who = await principal(db, x_api_key)
        async with db.session() as s:
            query = sa.select(Investigation)
            if who['role'] not in ('admin', 'open'):
                query = query.where(Investigation.id.in_(sa.select(CaseMember.case_id).where(
                    CaseMember.user_id == (who['user_id'] or -1))))
            total = await s.scalar(sa.select(sa.func.count()).select_from(query.subquery()))
            rows = (await s.scalars(query.order_by(Investigation.id.desc()).offset(offset).limit(limit))).all()
        return {"cases": [plain(r) for r in rows], "total": total}

    @app.post("/cases", dependencies=auth)
    async def create_case(payload: CaseInput, x_api_key: str | None = Header(None)):
        identity = await principal(db, x_api_key)
        who = identity["actor"]
        async with db.write_session() as s:
            if identity['role'] == 'viewer':
                raise HTTPException(403, 'Read-only account')
            row = Investigation(**payload.model_dump())
            s.add(row)
            await s.flush()
            if identity['user_id']:
                s.add(CaseMember(case_id=row.id, user_id=identity['user_id'], permission='write'))
            await audit(s, who, 'case_created', {'case_id': row.id, 'name': row.name})
            s.add(CaseActivity(case_id=row.id, action="created", actor=who, detail=row.name))
            await s.commit()
            return plain(row)

    @app.put("/cases/{case_id}", dependencies=auth)
    async def update_case(case_id: int, payload: CaseInput,
                          x_api_key: str | None = Header(None)):
        identity = await principal(db, x_api_key)
        who = identity["actor"]
        async with db.write_session() as s:
            row = await require_case(s, case_id, identity, write=True)
            before = {k: getattr(row, k) for k in payload.model_dump()}
            for k, v in payload.model_dump().items():
                setattr(row, k, v)
            await audit(s, who, 'case_updated', {'case_id': case_id, 'before': before, 'after': payload.model_dump()})
            s.add(CaseActivity(case_id=case_id, action="updated", actor=who,
                               detail=json.dumps({"before": before, "after": payload.model_dump()})))
            await s.commit()
            return plain(row)

    @app.get("/cases/{case_id}", dependencies=auth)
    async def case_detail(case_id: int, x_api_key: str | None = Header(None)):
        identity = await principal(db, x_api_key)
        async with db.session() as s:
            row = await require_case(s, case_id, identity)
            items = (await s.execute(sa.select(CaseItem, PageVersion).outerjoin(
                PageVersion, PageVersion.id == CaseItem.version_id
            ).options(sa.orm.defer(PageVersion.raw_body), sa.orm.defer(PageVersion.content))
                .where(CaseItem.case_id == case_id).order_by(CaseItem.id))).all()
            activity = (await s.execute(sa.select(CaseActivity).where(
                CaseActivity.case_id == case_id
            ).order_by(CaseActivity.id.desc()).limit(100))).scalars().all()
            return {"case": plain(row), "items": [dict(plain(i), available=v is not None,
                    capture=describe(v) if v else None) for i, v in items],
                    "activity": [plain(a) for a in activity]}

    @app.post("/cases/{case_id}/items", dependencies=auth)
    async def save_item(case_id: int, payload: ItemInput,
                        x_api_key: str | None = Header(None)):
        identity = await principal(db, x_api_key)
        who = identity["actor"]
        async with db.write_session() as s:
            await require_case(s, case_id, identity, write=True)
            version = await s.get(PageVersion, payload.version_id)
            if version is None:
                raise HTTPException(404, "Version unavailable")
            item = (await s.execute(sa.select(CaseItem).where(
                CaseItem.case_id == case_id, CaseItem.version_id == payload.version_id
            ))).scalar_one_or_none()
            if item is None:
                item = CaseItem(case_id=case_id, page_url=version.page_url, **payload.model_dump())
                s.add(item)
            else:
                for k, v in payload.model_dump().items():
                    setattr(item, k, v)
            await audit(s, who, 'exhibit_reviewed', {'case_id': case_id, **payload.model_dump()})
            s.add(CaseActivity(case_id=case_id, action="item_saved", actor=who,
                               detail=json.dumps(payload.model_dump())))
            await s.commit()
            return plain(item)

    @app.get("/cases/{case_id}/export", dependencies=auth)
    async def export_case(case_id: int, x_api_key: str | None = Header(None)):
        detail = await case_detail(case_id, x_api_key)
        ids = [i["version_id"] for i in detail["items"]]
        if not ids:
            raise HTTPException(400, "Save at least one page version first")
        if any(not i["available"] for i in detail["items"]):
            raise HTTPException(409, "A saved version was removed; export would be incomplete")
        body, summary = await build_bundle(db, case_name=detail["case"]["name"],
            version_ids=ids, limit=len(ids), signing_key=settings.evidence_signing_key,
            case_metadata=json.loads(json.dumps(detail, default=str)))
        if summary["items"] != len(ids):
            raise HTTPException(409, "A version was removed during export; retry after review")
        identity = await principal(db, x_api_key)
        who = identity["actor"]
        async with db.write_session() as s:
            await case_access(s, case_id, identity)
            await audit(s, who, 'case_exported', {'case_id': case_id, 'sha256': hashlib.sha256(body).hexdigest()})
            s.add(CaseActivity(case_id=case_id, action="exported", actor=who,
                detail=json.dumps({"sha256": hashlib.sha256(body).hexdigest(),
                                   "versions": ids, "bytes": len(body)})))
            await s.commit()
        return Response(body, media_type="application/zip", headers={
            "Content-Disposition": f'attachment; filename="case-{case_id}.zip"'})

    @app.get("/relationships", dependencies=auth)
    async def relationships(limit: int = Query(100, ge=1, le=500),
                            offset: int = Query(0, ge=0)):
        return await relationship_rows(db, limit=limit, offset=offset)

    @app.put("/relationships/review", dependencies=auth)
    async def review(payload: ReviewInput, x_api_key: str | None = Header(None)):
        from ..intel.entities import STRONG_TYPES, resolve_actors
        if payload.left == payload.right or any(
            t not in STRONG_TYPES or not v or len(v) > 512
            for t, v in (payload.left, payload.right)
        ):
            raise HTTPException(400, "Choose two distinct supported identifiers")
        left, right = sorted([payload.left, payload.right])
        identity = await principal(db, x_api_key)
        who = identity["actor"]
        if identity["role"] == "viewer":
            raise HTTPException(403, "Read-only account")
        key = pair_key(left, right)
        async with db.write_session() as s:
            row = await s.get(RelationshipReview, key)
            if row is None:
                row = RelationshipReview(pair_key=key, left_type=left[0], left_value=left[1],
                    right_type=right[0], right_value=right[1])
                s.add(row)
            before_verdict = row.verdict
            row.verdict, row.reason, row.reviewer = payload.verdict, payload.reason, who
            row.reviewed_at = utcnow()
            await audit(s, who, 'relationship_reviewed', {'key': key, 'before': before_verdict, 'after': payload.model_dump()})
            await s.commit()
        await resolve_actors(db)
        return {"key": key, "verdict": payload.verdict}
