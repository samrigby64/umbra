import hashlib
import json
import sqlite3
from contextlib import asynccontextmanager

import httpx
import pytest
import sqlalchemy as sa

from umbra.access import audit
from umbra.alerting import evaluate_watchlists
from umbra.api import create_app
from umbra.config import Settings
from umbra.db import Database
from umbra.maintenance import backup, restore
from umbra.models import AuditEntry, Event, Ioc, Page, PageVersion, Watchlist, utcnow


@asynccontextmanager
async def lab(tmp_path):
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'lab.db'}",
        embedder_kind="hashing",
        use_tor=False,
        backup_interval_hours=0,
    )
    db = Database(settings.database_url)
    await db.create_all()
    app = create_app(settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield db, c, settings
    await db.dispose()


async def seed(db):
    body = b"<p>contact seller example &lt;script&gt; SECRET</p>"
    digest = hashlib.sha256(body).hexdigest()
    async with db.write_session() as s:
        for i in range(3):
            url = f"http://example.onion/{i}"
            s.add(
                Page(
                    url=url,
                    hostname="example.onion",
                    title="Contact seller",
                    content="contact seller SECRET <script>alert(1)</script>"
                    + (" login" if i == 2 else ""),
                    status="crawled",
                    blocked=False,
                    stored_content=True,
                    raw_body=body,
                    content_sha256=digest,
                    body_truncated=i == 2,
                    content_captured_at=utcnow(),
                )
            )
            s.add(
                Ioc(
                    page_url=url,
                    ioc_type="handle",
                    value="ExampleSeller",
                    context="Contact ExampleSeller",
                )
            )
            s.add(
                PageVersion(
                    page_url=url,
                    title="Example",
                    content="SECRET <script>alert(1)</script>",
                    body_sha256=digest,
                    raw_body=body,
                    body_truncated=False,
                    captured_at=utcnow(),
                )
            )
        await s.commit()


async def test_search_duplicates_and_graph(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        await seed(db)
        r = await c.get("/workspace/search", params={"q": '"contact seller" -login'})
        assert r.status_code == 200, r.text
        assert r.json()["total"] == 2 and r.json()["engine"] == "fts5"
        assert (await c.get("/workspace/search", params={"q": '"unfinished'})).status_code == 400
        assert (await c.get("/workspace/search", params={"q": "-login"})).json()["total"] == 2
        assert (await c.get("/workspace/search", params={"since": "2030-01-01"})).json()[
            "total"
        ] == 0
        assert (await c.get("/workspace/search", params={"host": "different.onion"})).json()[
            "total"
        ] == 0
        dup = (await c.get("/workspace/duplicates")).json()
        assert dup["groups"][0]["count"] == 2  # Never merge a truncated-prefix match.
        assert dup["unique_indicators"] == 1 and dup["indicator_observations"] == 3
        graph = (await c.get("/workspace/graph", params={"value": "ExampleSeller"})).json()
        assert len(graph["edges"]) == 3 and all(
            e["context"] and e["observed_at"] for e in graph["edges"]
        )
        async with db.write_session() as s:
            await s.execute(
                sa.update(Page)
                .where(Page.url.endswith("/0"))
                .values(content="replaced", title="replaced")
            )
            await s.execute(sa.update(Page).where(Page.url.endswith("/1")).values(blocked=True))
            await s.commit()
        assert (await c.get("/workspace/search", params={"q": '"contact seller" -login'})).json()[
            "total"
        ] == 0


async def account(c, name, role="admin", headers=None):
    credentials = {"username": name, "password": "test-only-password-12345"}
    created = await c.post("/team", json={**credentials, "role": role}, headers=headers or {})
    assert created.status_code == 200, created.text
    signed = await c.post("/auth/login", json=credentials)
    assert signed.status_code == 200, signed.text
    return created.json()["id"], {"X-API-Key": signed.json()["token"]}


async def test_case_export_rechecks_membership_after_build(tmp_path, monkeypatch):
    from umbra.api import investigations
    from umbra.models import CaseMember
    async with lab(tmp_path) as (db, c, _):
        await seed(db)
        _, admin = await account(c, "admin")
        alice_id, alice = await account(c, "alice", "analyst", admin)
        case = (await c.post("/cases", json={"name": "Revoked during export"}, headers=alice)).json()["id"]
        assert (await c.post(f"/cases/{case}/items", json={"version_id": 1}, headers=alice)).status_code == 200
        original = investigations.build_bundle
        async def revoked_during_build(*args, **kwargs):
            result = await original(*args, **kwargs)
            async with db.write_session() as s:
                await s.execute(sa.delete(CaseMember).where(
                    CaseMember.case_id == case, CaseMember.user_id == alice_id))
                await s.commit()
            return result
        monkeypatch.setattr(investigations, "build_bundle", revoked_during_build)
        assert (await c.get(f"/cases/{case}/export", headers=alice)).status_code == 403


async def test_accounts_case_acl_sessions_and_saved_search_privacy(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        await seed(db)
        _, admin = await account(c, "admin")
        alice_id, alice = await account(c, "alice", "analyst", admin)
        _, bob = await account(c, "bob", "analyst", admin)
        assert (await c.get("/cases")).status_code == 401
        case = (await c.post("/cases", json={"name": "Private case"}, headers=alice)).json()["id"]
        assert (await c.get("/cases", headers=bob)).json()["total"] == 0
        for suffix in ("", "/export", "/members"):
            assert (await c.get(f"/cases/{case}" + suffix, headers=bob)).status_code == 403
        assert (await c.post(f"/cases/{case}/report", json={}, headers=bob)).status_code == 403
        assert (
            await c.post(f"/cases/{case}/items", json={"version_id": 1}, headers=alice)
        ).status_code == 200
        assert (
            await c.put(
                f"/cases/{case}/members",
                json={"user_id": alice_id, "permission": "read"},
                headers=alice,
            )
        ).status_code == 403
        assert (
            await c.put(
                f"/cases/{case}/members",
                json={"user_id": alice_id, "permission": "read"},
                headers=admin,
            )
        ).status_code == 200
        assert (
            await c.post(f"/cases/{case}/items", json={"version_id": 2}, headers=alice)
        ).status_code == 403
        assert (await c.get(f"/cases/{case}", headers=alice)).status_code == 200
        await c.post(
            "/workspace/saved-searches",
            json={"name": "Private query", "query": {"q": "SECRET"}},
            headers=alice,
        )
        assert (
            len((await c.get("/workspace/saved-searches", headers=alice)).json()["searches"]) == 1
        )
        assert not (await c.get("/workspace/saved-searches", headers=bob)).json()["searches"]
        await c.post("/auth/logout", headers=bob)
        assert (await c.get("/cases", headers=bob)).status_code == 401
        await c.post(f"/team/{alice_id}/disable", headers=admin)
        assert (await c.get("/cases", headers=alice)).status_code == 401
        assert (await c.get("/audit/verify", headers=admin)).json()["valid"]


async def test_report_redaction_does_not_change_original_and_review_history(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        await seed(db)
        case = (
            await c.post(
                "/cases", json={"name": "SECRET investigation", "notes": "SECRET conclusion"}
            )
        ).json()["id"]
        await c.post(
            f"/cases/{case}/items", json={"version_id": 1, "notes": "SECRET interpretation"}
        )
        r = await c.post(f"/cases/{case}/report", json={"redactions": ["SECRET"]})
        assert r.status_code == 200, r.text
        assert "SECRET" not in r.text and "[REDACTED]" in r.text
        assert "<script>" not in r.text and "&lt;script&gt;" in r.text
        async with db.session() as s:
            assert "SECRET" in (await s.get(PageVersion, 1)).content
        for verdict in ["confirmed", "rejected"]:
            r = await c.put(
                "/relationships/review",
                json={
                    "left": ["handle", "ExampleSeller"],
                    "right": ["btc", "wallet-demo"],
                    "verdict": verdict,
                    "reason": "reviewed example evidence",
                },
            )
            assert r.status_code == 200, r.text
        log = (await c.get("/audit")).json()["entries"]
        reviews = [json.loads(r["detail"]) for r in log if r["action"] == "relationship_reviewed"]
        assert len(reviews) == 2 and reviews[0]["before"] == "confirmed"
        assert (await c.get("/audit/verify")).json()["valid"]


async def test_audit_atomic_append_only_and_backup_restore(tmp_path):
    async with lab(tmp_path) as (db, c, settings):
        await seed(db)
        async with db.write_session() as s:
            await audit(s, "test", "rollback", {})
            # No commit: the entry must not survive.
        assert (await c.get("/audit/verify")).json()["entries"] == 0
        async with db.write_session() as s:
            await audit(s, "test", "committed", {"sample": 1})
            await s.commit()
        with pytest.raises(sa.exc.DBAPIError):
            async with db.write_session() as s:
                await s.execute(sa.delete(AuditEntry))
                await s.commit()
        result = backup(settings.database_url)
        source = tmp_path / "backups" / result["file"]
        target = tmp_path / "restored.db"
        assert restore(source, target)["integrity"] == "ok"
        with sqlite3.connect(target) as conn:
            assert conn.execute("select count(*) from pages").fetchone()[0] == 3
            assert conn.execute("select count(*) from pages_fts").fetchone()[0] == 3
        with pytest.raises(ValueError, match="already exists"):
            restore(source, target)
        source.write_bytes(b"corrupt")
        with pytest.raises(ValueError, match="checksum"):
            restore(source, tmp_path / "other.db")


async def test_alert_dedup_churn_and_triage(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        await seed(db)
        async with db.write_session() as s:
            s.add(Watchlist(name="Example", kind="keyword", value="contact seller"))
            s.add(Watchlist(name="Changes", kind="event", value="page_changed"))
            s.add(
                PageVersion(
                    page_url="http://example.onion/0",
                    content="SECRET <script>alert(1)</script>",
                    captured_at=utcnow(),
                )
            )
            await s.flush()
            s.add(
                Event(
                    kind="page_changed",
                    page_url="http://example.onion/0",
                    summary="Markup changed",
                    occurred_at=utcnow(),
                )
            )
            await s.commit()
        result = await evaluate_watchlists(db)
        assert (
            result["new_alerts"] == 2
        )  # Exact aliases merged; truncated page kept separate; no markup alert.
        assert (await evaluate_watchlists(db))["new_alerts"] == 0
        alerts = (await c.get("/workspace/alerts")).json()["alerts"]
        a = alerts[0]["id"]
        r = await c.put(
            f"/workspace/alerts/{a}",
            json={"status": "resolved", "assigned_to": "Analyst A", "notes": "Reviewed source"},
        )
        assert r.status_code == 200, r.text
        inbox = (await c.get("/workspace/alerts?status=resolved")).json()["alerts"]
        assert len(inbox) == 1 and inbox[0]["assigned_to"] == "Analyst A"
        assert (await c.get("/audit/verify")).json()["valid"]


async def test_operations_and_ui_assets(tmp_path):
    async with lab(tmp_path) as (_, c, _):
        r = await c.post("/operations/check-tor")
        assert r.json()["ok"] is False and "disabled" in r.json()["detail"]
        assert (await c.post("/operations/backup")).json()["integrity"] == "ok"
        support = (await c.get("/operations/support-bundle")).json()
        assert support["paid_ai_enabled"] is False and "no keys" in support["notice"]
        assert (await c.get("/workspace.js")).status_code == 200
