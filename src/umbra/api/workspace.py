"""Investigator workspace and local operations endpoints."""

import asyncio
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
import shutil
import time
from collections import deque
from typing import Literal

import httpx
import sqlalchemy as sa
from fastapi import Header, HTTPException, Query, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..access import (
    audit,
    audit_digest,
    case_access,
    check_password,
    new_session,
    password_hash,
    principal,
)
from ..maintenance import backup, database_path
from ..models import (
    Alert,
    AlertReview,
    AuditEntry,
    CaseItem,
    CaseMember,
    Investigation,
    Ioc,
    LoginSession,
    Page,
    PageVersion,
    SavedSearch,
    UserAccount,
    Watchlist,
    RelationshipReview,
    utcnow,
)
from ..workspace_search import search_pages


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)


class AccountInput(Credentials):
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class LoginInput(Credentials):
    otp: str = Field(default="", max_length=6)


class MemberInput(BaseModel):
    user_id: int
    permission: Literal["read", "write", "remove"]


class SearchInput(BaseModel):
    q: str = Field(default="", max_length=1000)
    host: str = Field(default="", max_length=255)
    kind: str = Field(default="", max_length=32)
    since: dt.date | None = None
    until: dt.date | None = None


class SaveSearchInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    query: SearchInput


class ReportInput(BaseModel):
    redactions: list[str] = Field(default_factory=list, max_length=100)


class TriageInput(BaseModel):
    status: Literal["new", "acknowledged", "resolved"]
    assigned_to: str = Field(default="", max_length=255)
    notes: str = Field(default="", max_length=4000)


def register(app, db, settings, auth, admin):
    login_attempts = deque(maxlen=100)
    password_slots = asyncio.Semaphore(2)

    @app.post("/auth/login")
    async def login(payload: LoginInput):
        now = time.monotonic()
        while login_attempts and login_attempts[0] < now - 60:
            login_attempts.popleft()
        if len(login_attempts) >= 30:
            raise HTTPException(429, "Too many sign-in attempts; retry in a minute")
        login_attempts.append(now)
        # Password derivation is deliberately expensive and never blocks the event loop.
        async with db.session() as s:
            user = await s.scalar(
                sa.select(UserAccount).where(UserAccount.username == payload.username.lower())
            )
        stored = user.password_hash if user else "0" * 32 + "$" + "0" * 64
        async with password_slots:
            valid = await asyncio.to_thread(check_password, payload.password, stored)
        if not valid or not user or not user.active:
            raise HTTPException(401, "Invalid credentials")
        async with db.write_session() as s:
            current = await s.get(UserAccount, user.id)
            if not current.active or current.password_hash != stored:
                raise HTTPException(401, "Account changed; sign in again")
            if current.totp_secret:
                from ..security import verify_totp
                verify_totp(current, payload.otp, settings)
            token = await new_session(s, current)
            await audit(s, f"user:{user.id}:{user.username}", "signed_in", {})
            await s.commit()
        return {"token": token, "expires_in": 28800, "role": user.role}

    @app.get("/auth/me", dependencies=auth)
    async def me(x_api_key: str | None = Header(None)):
        return await principal(db, x_api_key)

    @app.post("/auth/logout", dependencies=auth)
    async def logout(x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        async with db.write_session() as s:
            await s.execute(
                sa.delete(LoginSession).where(
                    LoginSession.token_hash
                    == hashlib.sha256((x_api_key or "").encode()).hexdigest()
                )
            )
            await audit(s, who, "signed_out", {})
            await s.commit()
        return {"signed_out": True}

    @app.get("/team", dependencies=admin)
    async def team():
        async with db.session() as s:
            rows = (
                (
                    await s.execute(
                        sa.select(
                            UserAccount.id,
                            UserAccount.username,
                            UserAccount.role,
                            UserAccount.active,
                        )
                    )
                )
                .mappings()
                .all()
            )
        return {"users": [dict(r) for r in rows]}

    @app.post("/team", dependencies=admin)
    async def add_user(payload: AccountInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        hashed = await asyncio.to_thread(password_hash, payload.password)
        async with db.write_session() as s:
            if await s.scalar(
                sa.select(UserAccount.id).where(UserAccount.username == payload.username.lower())
            ):
                raise HTTPException(409, "Username already exists")
            # A first account must be able to administer the installation after it closes local-open mode.
            count = await s.scalar(sa.select(sa.func.count()).select_from(UserAccount))
            if count == 0 and payload.role != "admin":
                raise HTTPException(400, "Create an administrator account first")
            row = UserAccount(
                username=payload.username.lower(), password_hash=hashed, role=payload.role
            )
            s.add(row)
            await s.flush()
            await audit(
                s, who, "user_created", {"id": row.id, "username": row.username, "role": row.role}
            )
            await s.commit()
        return {"id": row.id, "username": row.username, "role": row.role}

    @app.post("/team/{user_id}/disable", dependencies=admin)
    async def disable_user(user_id: int, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        async with db.write_session() as s:
            user = await s.get(UserAccount, user_id)
            if not user:
                raise HTTPException(404, "User not found")
            if user.role == "admin" and user.active:
                count = await s.scalar(
                    sa.select(sa.func.count())
                    .select_from(UserAccount)
                    .where(UserAccount.active.is_(True), UserAccount.role == "admin")
                )
                if count <= 1:
                    raise HTTPException(409, "Keep at least one active administrator")
            user.active = False
            await s.execute(sa.delete(LoginSession).where(LoginSession.user_id == user_id))
            await audit(s, who, "user_disabled", {"id": user_id})
            await s.commit()
        return {"disabled": user_id}

    @app.get("/cases/{case_id}/members", dependencies=auth)
    async def members(case_id: int, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        async with db.session() as s:
            await case_access(s, case_id, who)
            rows = (
                (
                    await s.execute(
                        sa.select(CaseMember.user_id, UserAccount.username, CaseMember.permission)
                        .join(UserAccount, UserAccount.id == CaseMember.user_id)
                        .where(CaseMember.case_id == case_id)
                    )
                )
                .mappings()
                .all()
            )
        return {"members": [dict(r) for r in rows]}

    @app.put("/cases/{case_id}/members", dependencies=admin)
    async def grant(case_id: int, payload: MemberInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        async with db.write_session() as s:
            if not await s.get(Investigation, case_id) or not await s.get(
                UserAccount, payload.user_id
            ):
                raise HTTPException(404, "Case or user not found")
            old = await s.get(CaseMember, (case_id, payload.user_id))
            if old:
                await s.delete(old)
                await s.flush()
            if payload.permission != "remove":
                s.add(
                    CaseMember(
                        case_id=case_id, user_id=payload.user_id, permission=payload.permission
                    )
                )
            await audit(s, who, "case_membership", {"case_id": case_id, **payload.model_dump()})
            await s.commit()
        return {"saved": True}

    @app.get("/audit", dependencies=admin)
    async def audit_log(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        async with db.session() as s:
            rows = (
                await s.scalars(
                    sa.select(AuditEntry).order_by(AuditEntry.id.desc()).offset(offset).limit(limit)
                )
            ).all()
        return {
            "entries": [
                {k: getattr(r, k) for k in ("id", "actor", "action", "detail", "at", "entry_hash")}
                for r in rows
            ]
        }

    @app.get("/audit/verify", dependencies=admin)
    async def verify_audit():
        previous, count = "0" * 64, 0
        async with db.session() as s:
            stream = await s.stream_scalars(
                sa.select(AuditEntry).order_by(AuditEntry.id).execution_options(yield_per=200)
            )
            async for row in stream:
                if row.previous_hash != previous or row.entry_hash != audit_digest(
                    previous, row.actor, row.action, row.detail, row.at
                ):
                    return {"valid": False, "failed_id": row.id}
                previous, count = row.entry_hash, count + 1
        return {
            "valid": True,
            "entries": count,
            "head_hash": previous,
            "notice": "Export and retain this head separately. A database administrator can replace the entire log.",
        }

    @app.get("/workspace/search", dependencies=auth)
    async def text_search(
        q: str = Query("", max_length=1000),
        host: str = "",
        kind: str = "",
        since: dt.date | None = None,
        until: dt.date | None = None,
        limit: int = Query(30, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        try:
            return await search_pages(
                db, q=q, host=host, kind=kind, since=since, until=until, limit=limit, offset=offset
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/workspace/saved-searches", dependencies=auth)
    async def saved_searches(x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        async with db.session() as s:
            rows = (
                await s.scalars(
                    sa.select(SavedSearch)
                    .where(SavedSearch.owner == who["actor"])
                    .order_by(SavedSearch.id)
                )
            ).all()
        return {
            "searches": [{"id": r.id, "name": r.name, "query": json.loads(r.query)} for r in rows]
        }

    @app.post("/workspace/saved-searches", dependencies=auth)
    async def save_search(payload: SaveSearchInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        async with db.write_session() as s:
            row = SavedSearch(
                owner=who["actor"], name=payload.name, query=payload.query.model_dump_json()
            )
            s.add(row)
            await s.commit()
        return {"id": row.id}

    @app.get("/workspace/duplicates", dependencies=auth)
    async def duplicates(limit: int = Query(30, ge=1, le=100), offset: int = Query(0, ge=0)):
        # Truncated-prefix hashes cannot establish full-body equality.
        eligible = (
            Page.blocked.is_(False),
            Page.content_sha256.is_not(None),
            Page.body_truncated.is_(False),
        )
        grouped = (
            sa.select(Page.content_sha256.label("sha"), sa.func.count().label("n"))
            .where(*eligible)
            .group_by(Page.content_sha256)
        )
        async with db.session() as s:
            groups = (
                await s.execute(
                    grouped.having(sa.func.count() > 1)
                    .order_by(sa.func.count().desc(), Page.content_sha256)
                    .offset(offset)
                    .limit(limit)
                )
            ).all()
            counts = await s.scalar(sa.select(sa.func.count()).select_from(grouped.subquery()))
            observations = await s.scalar(sa.select(sa.func.count()).select_from(Ioc))
            distinct = await s.scalar(
                sa.select(sa.func.count()).select_from(
                    sa.select(Ioc.ioc_type, Ioc.value).distinct().subquery()
                )
            )
            result = []
            for sha, n in groups:
                rows = (
                    (
                        await s.execute(
                            sa.select(Page.url, Page.hostname, Page.content_captured_at)
                            .where(*eligible, Page.content_sha256 == sha)
                            .order_by(Page.url)
                            .limit(100)
                        )
                    )
                    .mappings()
                    .all()
                )
                result.append({"sha256": sha, "count": n, "sources": [dict(r) for r in rows]})
        return {
            "groups": result,
            "unique_complete_bodies": counts,
            "indicator_observations": observations,
            "unique_indicators": distinct,
            "offset": offset,
            "limit": limit,
            "notice": "Exact retained-body matches only; identical content does not establish common ownership. Every source and capture remains intact.",
        }

    @app.get("/workspace/graph", dependencies=auth)
    async def graph(value: str = Query(..., min_length=1, max_length=512)):
        async with db.session() as s:
            urls = list(
                (
                    await s.scalars(
                        sa.select(Ioc.page_url)
                        .join(Page, Page.url == Ioc.page_url)
                        .where(Ioc.value == value, Page.blocked.is_(False))
                        .distinct()
                        .order_by(Ioc.page_url)
                        .limit(31)
                    )
                ).all()
            )
            reviews = (
                await s.scalars(
                    sa.select(RelationshipReview)
                    .where(
                        sa.or_(
                            RelationshipReview.left_value == value,
                            RelationshipReview.right_value == value,
                        )
                    )
                    .limit(100)
                )
            ).all()
            rows = []
            for url in urls[:30]:
                rows.extend(
                    (
                        await s.execute(
                            sa.select(
                                Ioc.ioc_type,
                                Ioc.value,
                                Ioc.page_url,
                                Ioc.context,
                                Page.content_captured_at,
                            )
                            .join(Page, Page.url == Ioc.page_url)
                            .where(Ioc.page_url == url)
                            .order_by(Ioc.id)
                            .limit(101)
                        )
                    ).all()
                )
        nodes, edges = {}, []
        for kind, val, url, context, at in rows:
            key = hashlib.sha256((kind + "\0" + val).encode()).hexdigest()
            source = hashlib.sha256(url.encode()).hexdigest()
            nodes[key] = {"id": key, "kind": kind, "label": val}
            nodes[source] = {"id": source, "kind": "source", "label": url}
            edges.append(
                {"from": key, "to": source, "context": context, "observed_at": at, "url": url}
            )
        review_rows = []
        for r in reviews:
            left = (r.left_type, r.left_value)
            right = (r.right_type, r.right_value)
            contexts = {}
            for kind, val, url, context, at in rows:
                contexts.setdefault(url, {})[(kind, val)] = context
            sources = [
                {"url": url, "left_context": c[left], "right_context": c[right]}
                for url, c in contexts.items()
                if left in c and right in c
            ]
            review_rows.append(
                {
                    "key": r.pair_key,
                    "left": left,
                    "right": right,
                    "verdict": r.verdict,
                    "reason": r.reason,
                    "reviewer": r.reviewer,
                    "reviewed_at": r.reviewed_at,
                    "sources": sources[:10],
                    "source_count": len(sources),
                }
            )
        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "reviews": review_rows,
            "limited": len(urls) > 30 or any(sum(e["url"] == u for e in edges) > 100 for u in urls),
            "notice": "Edges mean observed on this source, not identity or ownership. Up to 30 sources and 101 observations per source.",
        }

    @app.post("/cases/{case_id}/report", dependencies=auth)
    async def report(case_id: int, payload: ReportInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        if any(not t.strip() or len(t) > 512 for t in payload.redactions):
            raise HTTPException(
                400, "Redactions must be nonempty literal strings, at most 512 characters each"
            )

        def escaped(value):
            value = str(value or "")
            for term in sorted(payload.redactions, key=len, reverse=True):
                value = value.replace(term, "[REDACTED]")
            return html.escape(value)

        async with db.write_session() as s:
            await case_access(s, case_id, who)
            case = await s.get(Investigation, case_id)
            if not case:
                raise HTTPException(404, "Case not found")
            items = (
                await s.execute(
                    sa.select(CaseItem, PageVersion)
                    .outerjoin(PageVersion, PageVersion.id == CaseItem.version_id)
                    .options(sa.orm.defer(PageVersion.raw_body))
                    .where(CaseItem.case_id == case_id)
                    .order_by(PageVersion.captured_at, CaseItem.id)
                )
            ).all()
            if not items:
                raise HTTPException(400, "Save an exhibit first")
            parts = [
                '<!doctype html><html><head><meta charset="utf-8"><title>Case report</title><style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}article{border-top:1px solid #888;padding-top:20px}small{overflow-wrap:anywhere}@media print{article{break-inside:avoid}}</style></head><body>',
                f"<h1>{escaped(case.name)}</h1><p>Generated {escaped(utcnow().isoformat())}</p><p>Assigned analyst: {escaped(case.assigned_to)}</p>",
                "<h2>Analyst notes and conclusions</h2><pre>" + escaped(case.notes) + "</pre>",
                "<h2>Source observations</h2><p>Capture times are observation times, not dates of underlying events. Statements on source pages are unverified source claims. Redactions apply to this report only; original evidence is unchanged.</p>",
            ]
            for item, v in items:
                parts.append(
                    f"<article><h3>Exhibit {item.id} · Version {item.version_id}</h3><p>Source: {escaped(item.page_url)}</p><p>Assessment: {escaped(item.verdict)}</p><h4>Analyst interpretation</h4><pre>{escaped(item.notes)}</pre>"
                )
                if v:
                    parts.append(
                        f"<p>Captured: {escaped(v.captured_at or 'Unknown (legacy)')}</p><small>Retained body SHA-256: {escaped(v.body_sha256)} · Truncated: {v.body_truncated is True} · Legacy: {bool(v.legacy)}</small><h4>Observed page text (excerpt, up to 20,000 characters)</h4><pre>{escaped((v.content or '')[:20000])}</pre>"
                    )
                else:
                    parts.append(
                        "<p>Capture unavailable: removed by retention or policy. This report is incomplete.</p>"
                    )
                parts.append("</article>")
            parts.append("</body></html>")
            body = "\n".join(parts).encode()
            await audit(
                s,
                who,
                "report_exported",
                {
                    "case_id": case_id,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "redaction_count": len(payload.redactions),
                },
            )
            await s.commit()
        return Response(
            body,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="case-{case_id}-report.html"',
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            },
        )

    @app.get("/workspace/alerts", dependencies=auth)
    async def inbox(status: str = "", limit: int = Query(100, ge=1, le=500)):
        async with db.session() as s:
            query = (
                sa.select(Alert, Watchlist.name, AlertReview)
                .join(Watchlist, Watchlist.id == Alert.watchlist_id)
                .outerjoin(AlertReview, AlertReview.alert_id == Alert.id)
            )
            if status:
                query = query.where(sa.func.coalesce(AlertReview.status, "new") == status)
            rows = (await s.execute(query.order_by(Alert.id.desc()).limit(limit))).all()
        return {
            "alerts": [
                {
                    "id": a.id,
                    "watchlist": name,
                    "url": a.page_url,
                    "match": a.matched_value,
                    "at": a.created_at,
                    "status": r.status if r else "new",
                    "assigned_to": r.assigned_to if r else "",
                    "notes": r.notes if r else "",
                }
                for a, name, r in rows
            ]
        }

    @app.put("/workspace/alerts/{alert_id}", dependencies=auth)
    async def triage(alert_id: int, payload: TriageInput, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        if who["role"] == "viewer":
            raise HTTPException(403, "Read-only account")
        async with db.write_session() as s:
            if not await s.get(Alert, alert_id):
                raise HTTPException(404, "Alert not found")
            row = await s.get(AlertReview, alert_id)
            if not row:
                row = AlertReview(alert_id=alert_id)
                s.add(row)
            before = {"status": row.status, "assigned_to": row.assigned_to, "notes": row.notes}
            for k, v in payload.model_dump().items():
                setattr(row, k, v)
            row.updated_at = utcnow()
            await audit(
                s,
                who,
                "alert_triaged",
                {"id": alert_id, "before": before, "after": payload.model_dump()},
            )
            await s.commit()
        return {"saved": True}

    @app.get("/operations", dependencies=admin)
    async def operations():
        try:
            path = database_path(settings.database_url)
            storage = {
                "bytes": sum(p.stat().st_size for p in
                             (path, Path(str(path)+"-wal"), Path(str(path)+"-shm")) if p.exists()),
                "free_bytes": shutil.disk_usage(path.parent).free,
            }
            manifests = sorted((path.parent / "backups").glob("*.json"), reverse=True)[:20]
            backups = [json.loads(p.read_text()) for p in manifests]
        except (ValueError, OSError):
            storage, backups = {}, []
        return {
            "version": __version__,
            "preview": settings.preview_mode,
            "beta_mode": settings.beta_mode,
            "tor_enabled": settings.use_tor,
            "paid_ai_enabled": settings.llm_enabled,
            "search_model": settings.embedder_kind,
            "storage": storage,
            "backups": backups,
        }

    @app.post("/operations/check-tor", dependencies=admin)
    async def check_tor():
        if not settings.use_tor:
            return {"ok": False, "detail": "Tor is disabled in configuration."}
        try:
            async with httpx.AsyncClient(
                proxy=f"socks5://{settings.tor_socks_host}:{settings.tor_socks_port}", timeout=20
            ) as client:
                async with asyncio.timeout(25):
                    result = await client.get("https://check.torproject.org/api/ip")
                    result.raise_for_status()
                    is_tor = result.json().get("IsTor") is True
            return {
                "ok": is_tor,
                "detail": "Tor exit verified. Individual onion services can still be unavailable."
                if is_tor
                else "Proxy connected but the Tor Project did not recognise a Tor exit.",
            }
        except Exception as e:
            return {
                "ok": False,
                "detail": f"Tor connectivity check failed ({type(e).__name__}). Start Tor, wait for bootstrap, and retry. A network without exit access can still reach onion services.",
            }

    @app.post("/operations/backup", dependencies=admin)
    async def make_backup(x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        try:
            from ..backup_crypto import key_path
            result = await asyncio.to_thread(backup, settings.database_url,
                                             key_file=key_path(settings))
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        async with db.write_session() as s:
            await audit(s, who, "backup_created", result)
            await s.commit()
        return result

    @app.get("/operations/support-bundle", dependencies=admin)
    async def support_bundle():
        report = await operations()
        report["notice"] = (
            "Contains operational configuration and backup hashes only; no keys, passwords, source URLs, case notes, or captured content."
        )
        return Response(
            json.dumps(report, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="umbra-diagnostics.json"'},
        )
