"""Collection quality, persistent schedules, and reviewed extraction examples."""
import json
from typing import Literal

import sqlalchemy as sa
from fastapi import Header, HTTPException, Response
from pydantic import BaseModel, Field, model_validator

from ..access import audit, principal
from ..collection_quality import quality
from ..jobs import describe
from ..models import CollectionJob, ExtractionFeedback, PageVersion, utcnow
from ..scope import allows, canonical_hosts, valid_host


class JobInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    seeds: list[str] = Field(min_length=1, max_length=100)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=100)
    strict_scope: bool = True
    max_depth: int = Field(default=1, ge=0, le=20)
    max_pages: int = Field(default=25, ge=1, le=10000)
    max_duration_s: int = Field(default=600, ge=10, le=86400)
    interval_s: int = Field(default=0, ge=0, le=31536000)
    store_html: bool = True

    @model_validator(mode="after")
    def scope(self):
        try:
            hosts = sorted({valid_host(url) for url in self.seeds})
            self.allowed_hosts = canonical_hosts(self.allowed_hosts)
            if self.strict_scope and not self.allowed_hosts:
                self.allowed_hosts = hosts
            if not all(allows(url, self.allowed_hosts) for url in self.seeds):
                raise ValueError("Seed outside allowed hosts")
            if 0 < self.interval_s < 60:
                raise ValueError("Recurring interval must be at least 60 seconds")
        except ValueError:
            raise
        return self


class FeedbackInput(BaseModel):
    version_id: int
    extractor: Literal["listings", "iocs"]
    value: str = Field(min_length=1, max_length=1024)
    verdict: Literal["correct", "false_positive", "missed"]
    reason: str = Field(min_length=1, max_length=4000)


def register(app, db, settings, auth, admin):
    @app.get("/collection/quality", dependencies=auth)
    async def collection_quality():
        return await quality(db)

    @app.get("/collection/jobs", dependencies=admin)
    async def jobs():
        async with db.session() as s:
            rows = (await s.scalars(sa.select(CollectionJob).order_by(
                CollectionJob.id.desc()).limit(200))).all()
            return {"jobs": [describe(r) for r in rows],
                    "notice": "Schedules run while the API is running. The installation shares one page frontier."}

    @app.post("/collection/jobs", dependencies=admin)
    async def create_job(payload: JobInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        config = payload.model_dump(exclude={"name", "interval_s"})
        async with db.write_session() as s:
            job = CollectionJob(name=payload.name, config=json.dumps(config),
                                interval_s=payload.interval_s)
            s.add(job)
            await s.flush()
            await audit(s, who, "collection_job_created", {"job_id": job.id})
            await s.commit()
            return describe(job)

    @app.post("/collection/jobs/{job_id}/{action}", dependencies=admin)
    async def control(job_id: int, action: Literal["resume", "pause"],
                      x_api_key: str | None = Header(None)):
        if settings.preview_mode and action == "resume":
            raise HTTPException(409, "Collection is disabled in the synthetic preview")
        who = await principal(db, x_api_key)
        async with db.write_session() as s:
            row = await s.get(CollectionJob, job_id)
            if not row:
                raise HTTPException(404, "Job not found")
            row.paused = action == "pause"
            if row.paused:
                row.status = "pausing" if row.lease_until and row.lease_until.replace(
                    tzinfo=utcnow().tzinfo) > utcnow() else "paused"
            else:
                row.next_run_at = utcnow()
                row.status = "scheduled"
            row.updated_at = utcnow()
            await audit(s, who, "collection_job_" + action, {"job_id": job_id})
            await s.commit()
            return describe(row)

    @app.post("/collection/feedback", dependencies=auth)
    async def feedback(payload: FeedbackInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        if who["role"] == "viewer":
            raise HTTPException(403, "Analyst role required")
        async with db.write_session() as s:
            version = await s.get(PageVersion, payload.version_id)
            if not version:
                raise HTTPException(404, "Retained version not found")
            row = ExtractionFeedback(**payload.model_dump(), page_url=version.page_url,
                                     reviewer=who["actor"])
            s.add(row)
            await s.flush()
            await audit(s, who, "extraction_reviewed", {"feedback_id": row.id,
                                                     "verdict": row.verdict})
            await s.commit()
            return {"id": row.id}

    @app.get("/collection/feedback", dependencies=auth)
    async def feedback_list():
        async with db.session() as s:
            rows = (await s.scalars(sa.select(ExtractionFeedback).order_by(
                ExtractionFeedback.id.desc()).limit(200))).all()
            return {"reviews": [{k: getattr(r, k) for k in (
                "id", "version_id", "page_url", "extractor", "value", "verdict", "reason",
                "reviewer", "created_at")} for r in rows]}

    @app.get("/collection/regression-examples", dependencies=admin)
    async def examples():
        async with db.session() as s:
            rows = (await s.execute(sa.select(ExtractionFeedback, PageVersion).join(
                PageVersion, PageVersion.id == ExtractionFeedback.version_id
            ).order_by(ExtractionFeedback.id).limit(500))).all()
            data = [{"review_id": r.id, "extractor": r.extractor, "expected": r.value,
                     "verdict": r.verdict, "text": (v.content or "")[:20000],
                     "body_sha256": v.body_sha256, "reason": r.reason} for r, v in rows]
        return Response(json.dumps({"schema_version": 1, "examples": data,
            "notice": "Reviewed test examples, not automatic training. Text excerpts are limited to 20,000 characters."}),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="extraction-examples.json"'})
