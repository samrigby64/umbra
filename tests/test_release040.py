import asyncio
import datetime as dt
import hashlib
import io
import json
import os
import sqlite3
import zipfile
import subprocess
import sys
from pathlib import Path
import re
import shutil
from contextlib import asynccontextmanager, closing

import httpx
import pyotp
import pytest
import sqlalchemy as sa

from umbra.api import create_app
from umbra.collection_quality import quality
from umbra.config import Settings
from umbra.crawl.parse import parse_page
from umbra.db import Database
from umbra.enrich.structured import ListingExtractor
from umbra.enrich.validation import bitcoin_base58_valid
from umbra.evidence import build_bundle
from umbra.jobs import claim, execute, finish
from umbra.maintenance import backup, restore
from umbra.models import CollectionJob, Page, PageVersion, Run, utcnow
from umbra.verify_evidence import verify


@asynccontextmanager
async def lab(tmp_path, **kwargs):
    settings = Settings(_env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path / 'lab.db'}",
                        embedder_kind="hashing", use_tor=False, backup_interval_hours=0,
                        security_key_file=str(tmp_path/"security.key"), **kwargs)
    db = Database(settings.database_url)
    await db.create_all()
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                base_url="http://test") as c:
        yield db, c, settings
    await db.dispose()


async def make_job(c, **extra):
    r = await c.post("/collection/jobs", json={
        "name": "Synthetic job", "seeds": ["https://fixture.example/"], **extra})
    assert r.status_code == 200, r.text
    return r.json()


async def test_jobs_are_saved_paused_validate_scope_and_recover_expired_lease(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        j = await make_job(c)
        assert j["paused"] and await claim(db) is None
        assert (await c.post("/collection/jobs", json={
            "name": "bad", "seeds": ["https://other.example/"],
            "allowed_hosts": ["fixture.example"]})).status_code == 422
        await c.post(f"/collection/jobs/{j['id']}/resume")
        first = await claim(db)
        assert first and await claim(db) is None
        async with db.write_session() as s:
            row = await s.get(CollectionJob, first.id)
            row.lease_until = utcnow()-dt.timedelta(seconds=1)
            await s.commit()
        second_db = Database(db._engine.url.render_as_string(hide_password=False))
        second = await claim(second_db)
        assert second.claim_seq > first.claim_seq
        assert not await finish(db, first, {}, "old")
        assert await finish(second_db, second, {"crawled": 2}, "page_budget_reached")
        await second_db.dispose()
        result = (await c.get("/collection/jobs")).json()["jobs"][0]
        assert result["status"] == "completed" and result["last_result"]["crawled"] == 2


async def test_pause_and_repeat_job(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        j = await make_job(c, interval_s=60)
        await c.post(f"/collection/jobs/{j['id']}/resume")
        first = await claim(db)
        await finish(db, first, {}, "no_eligible_pages_in_scope")
        result = (await c.get("/collection/jobs")).json()["jobs"][0]
        assert result["status"] == "scheduled" and await claim(db) is None
        await c.post(f"/collection/jobs/{j['id']}/resume")
        second = await claim(db)
        await c.post(f"/collection/jobs/{j['id']}/pause")
        await finish(db, second, {}, "no_eligible_pages_in_scope")
        result = (await c.get("/collection/jobs")).json()["jobs"][0]
        assert result["status"] == "paused" and result["next_run_at"] is None


async def test_job_executes_real_pipeline_with_fake_transport(tmp_path):
    from umbra.compliance.policy import CompliancePolicy
    from umbra.crawl.crawler import Crawler
    from umbra.crawl.scorer import KeywordScorer
    from umbra.fetch.client import FetchResult
    class Fetcher:
        closed = False
        async def fetch(self, url):
            body = b"<p>Synthetic evidence</p>"
            return FetchResult(url=url, ok=True, status=200, body=body, text=body.decode(),
                               content_type="text/html")
        async def aclose(self):
            self.closed = True
    fetcher = Fetcher()
    def builder(settings, db):
        return Crawler(settings, db, fetcher, KeywordScorer([]),
                       CompliancePolicy(store_html=True)), fetcher
    async with lab(tmp_path) as (db, c, settings):
        j = await make_job(c, max_pages=1, max_depth=0)
        await c.post(f"/collection/jobs/{j['id']}/resume")
        await execute(db, settings, await claim(db), builder)
        assert fetcher.closed
        result = (await c.get("/collection/jobs")).json()["jobs"][0]
        assert result["last_result"]["crawled"] == 1
        assert result["stop_reason"] == "page_budget_reached"
        async with db.session() as s:
            version = await s.scalar(sa.select(PageVersion))
            assert json.loads(version.capture_metadata)["settings"]["max_depth"] == 0
            assert (await s.scalar(sa.select(Run))).pages_crawled == 1


async def test_quality_preserves_counts_during_recrawl_and_excludes_truncated(tmp_path):
    async with lab(tmp_path) as (db, c, _):
        async with db.write_session() as s:
            for i in range(3):
                s.add(Page(url=f"https://fixture.example/{i}", hostname="fixture.example",
                           content="A"*90, status="in_progress", blocked=False,
                           content_sha256="a"*64, body_truncated=i == 2,
                           content_captured_at=utcnow(), extraction_errors='[]'))
            await s.commit()
        q = await quality(db)
        assert q["retained_pages"] == 3 and q["duplicate_rate"] == .5
        assert q["unique_substantive_pages"] == 1 and q["fresh_within_7_days"] == 3
        assert (await c.get("/overview")).json()["counts"]["pages"] == 3


async def test_structure_listing_boundaries_and_checksum_validation():
    parsed = parse_page("<table><tr><td>Notebook</td><td>$12</td></tr>"
                        "<tr><td>Pencil</td><td>$2</td></tr></table>", "https://fixture.example/")
    records = await ListingExtractor().enrich(Page(url=parsed.url), parsed)
    assert [(r.product, r.price) for r in records] == [("Notebook", 12), ("Pencil", 2)]
    assert bitcoin_base58_valid("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert not bitcoin_base58_valid("1BoatSLRHtKNngkdXEeobR76b53LETtpyU")


async def test_standalone_verifier_signed_tampered_and_missing_members(tmp_path):
    async with lab(tmp_path) as (db, _, _):
        body = b"<p>Fictional</p>"
        async with db.write_session() as s:
            s.add(Page(url="https://fixture.example/", hostname="fixture.example",
                       content="Fictional", blocked=False, raw_body=body,
                       content_sha256=hashlib.sha256(body).hexdigest(), body_truncated=False))
            await s.commit()
        data, _ = await build_bundle(db, signing_key="test key")
        bundle = tmp_path/"evidence.zip"
        bundle.write_bytes(data)
        assert verify(bundle, b"test key")["authenticated"]
        standalone = subprocess.run([sys.executable, "-I",
            str(Path(__file__).parents[1]/"src/umbra/verify_evidence.py"), str(bundle)],
            capture_output=True, text=True)
        assert standalone.returncode == 0, standalone.stderr
        assert json.loads(standalone.stdout)["valid"]
        assert not verify(bundle)["authenticated"]
        with pytest.raises(ValueError, match="authentication"):
            verify(bundle, b"wrong key")
        original = zipfile.ZipFile(io.BytesIO(data))
        for mode in ("tamper", "missing", "extra"):
            broken = tmp_path/(mode+".zip")
            with zipfile.ZipFile(broken, "w") as z:
                for name in original.namelist():
                    if mode == "missing" and name == "README.txt":
                        continue
                    z.writestr(name, b"tampered" if mode == "tamper" and
                               name == "README.txt" else original.read(name))
                if mode == "extra":
                    z.writestr("extra.txt", "undeclared")
            with pytest.raises(ValueError):
                verify(broken)


def test_encrypted_backup_roundtrip_wrong_key_tampering_and_exclusive_restore(tmp_path):
    source = tmp_path/"source.db"
    with closing(sqlite3.connect(source)) as s:
        s.execute("CREATE TABLE test(value TEXT)")
        s.execute("INSERT INTO test VALUES ('synthetic secret')")
        s.commit()
    key = tmp_path/"key"
    key.write_bytes(os.urandom(32))
    wrong = tmp_path/"wrong"
    wrong.write_bytes(os.urandom(32))
    meta = backup(f"sqlite:///{source}", tmp_path/"backups", key_file=key)
    encrypted = tmp_path/"backups"/meta["file"]
    assert b"synthetic secret" not in encrypted.read_bytes()
    assert not list((tmp_path/"backups").glob("*.db"))
    target = tmp_path/"restored.db"
    with pytest.raises(ValueError, match="authentication"):
        restore(encrypted, target, key_file=wrong)
    assert not target.exists()
    assert restore(encrypted, target, key_file=key)["authenticated"]
    with closing(sqlite3.connect(target)) as s:
        assert s.execute("SELECT value FROM test").fetchone()[0] == "synthetic secret"
    with pytest.raises(ValueError, match="already exists"):
        restore(encrypted, target, key_file=key)


async def test_mfa_replay_and_password_recovery_revoke_sessions(tmp_path, monkeypatch):
    # Fixed clock advances explicitly; no sleeping for authenticator periods.
    import umbra.security
    clock = [1800000000]
    monkeypatch.setattr(umbra.security.time, "time", lambda: clock[0])
    async with lab(tmp_path) as (_, c, _):
        account = {"username": "admin", "password": "test-only-password", "role": "admin"}
        assert (await c.post("/team", json=account)).status_code == 200
        login = await c.post("/auth/login", json=account)
        c.headers["X-API-Key"] = login.json()["token"]
        recovery = (await c.post("/team/1/recovery")).json()["token"]
        setup = await c.post("/auth/mfa/setup", json={"password": account["password"]})
        otp = pyotp.TOTP(setup.json()["secret"])
        assert (await c.post("/auth/mfa/confirm", json={"otp": otp.at(clock[0])})).status_code == 200
        assert (await c.get("/auth/me")).status_code == 401
        assert (await c.post("/auth/login", json={**account, "otp": otp.at(clock[0])})).status_code == 401
        clock[0] += 30
        login = await c.post("/auth/login", json={**account, "otp": otp.at(clock[0])})
        assert login.status_code == 200
        c.headers["X-API-Key"] = login.json()["token"]
        reset = {"token": recovery, "password": "new-test-password"}
        assert (await c.post("/auth/recover", json=reset)).status_code == 401
        clock[0] += 30
        assert (await c.post("/auth/recover", json={**reset, "otp": otp.at(clock[0])})).status_code == 200
        assert (await c.get("/auth/me")).status_code == 401
        assert (await c.post("/auth/recover", json=reset)).status_code == 401


async def test_feedback_exports_reproducible_examples(tmp_path):
    from umbra.feedback_eval import evaluate
    async with lab(tmp_path) as (db, c, _):
        async with db.write_session() as s:
            v = PageVersion(page_url="https://fixture.example/", content="Notebook $12")
            s.add(v)
            await s.commit()
        r = await c.post("/collection/feedback", json={
            "version_id": v.id, "extractor": "listings", "value": "Notebook",
            "verdict": "correct", "reason": "Matches synthetic table"})
        assert r.status_code == 200
        examples = (await c.get("/collection/regression-examples")).json()
        assert (await evaluate(examples))["passed"] == 1
        assert (await c.post("/collection/feedback", json={
            "version_id": 999, "extractor": "listings", "value": "x",
            "verdict": "missed", "reason": "missing version"})).status_code == 404


async def test_versioned_migration_concurrent_and_unknown_revision(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path/'migrate.db'}"
    a, b = Database(url), Database(url)
    await asyncio.gather(a.create_all(), b.create_all())
    async with a.write_session() as s:
        assert await s.scalar(sa.text("SELECT count(*) FROM schema_migrations")) == 1
        await s.execute(sa.text("UPDATE schema_migrations SET revision='999'"))
        await s.commit()
    with pytest.raises(RuntimeError, match="newer schema"):
        await b.create_all()
    await a.dispose()
    await b.dispose()


async def test_reprocessing_uses_rows_and_keeps_records_when_extractor_fails(tmp_path):
    from umbra.enrich.ioc import IocExtractor
    from umbra.models import Ioc, Listing
    from umbra.reprocess import reprocess_pages
    class Broken:
        name = "ioc"
        async def enrich(self, page, parsed):
            raise RuntimeError("Synthetic failure")
    async with lab(tmp_path) as (db, _, _):
        html = "<table><tr><td>Notebook</td><td>$12</td></tr><tr><td>Pencil</td><td>$2</td></tr></table>"
        url = "https://fixture.example/"
        async with db.write_session() as s:
            s.add(Page(url=url, hostname="fixture.example", status="crawled",
                       content="Notebook $12 Pencil $2", html=html, blocked=False))
            s.add(Ioc(page_url=url, ioc_type="handle", value="RetainedExample"))
            await s.commit()
        await reprocess_pages(db, [Broken(), ListingExtractor()])
        async with db.session() as s:
            assert await s.scalar(sa.select(Ioc.value)) == "RetainedExample"
            assert (await s.scalars(sa.select(Listing.product).order_by(Listing.id))).all() == [
                "Notebook", "Pencil"]
            page = await s.get(Page, url)
            assert json.loads(page.extraction_errors)[0]["error_type"] == "RuntimeError"
        await reprocess_pages(db, [IocExtractor(), ListingExtractor()])
        async with db.session() as s:
            assert (await s.get(Page, url)).extraction_errors == "[]"


async def test_interrupted_job_reclaims_its_abandoned_page(tmp_path):
    from umbra.compliance.policy import CompliancePolicy
    from umbra.crawl.crawler import Crawler
    from umbra.crawl.scorer import KeywordScorer
    from umbra.fetch.client import FetchResult
    started = asyncio.Event()
    class Fetcher:
        async def fetch(self, url):
            started.set()
            await asyncio.Event().wait()
        async def aclose(self):
            pass
    def builder(settings, db):
        return Crawler(settings, db, Fetcher(), KeywordScorer([]), CompliancePolicy()), Fetcher()
    async with lab(tmp_path) as (db, c, settings):
        j = await make_job(c, max_pages=1)
        await c.post(f"/collection/jobs/{j['id']}/resume")
        task = asyncio.create_task(execute(db, settings, await claim(db), builder))
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with db.write_session() as s:
            job = await s.get(CollectionJob, j["id"])
            assert job.status == "running" and not job.paused
            job.lease_until = utcnow()-dt.timedelta(seconds=1)
            page = await s.get(Page, "https://fixture.example/")
            page.claimed_at = utcnow()-dt.timedelta(seconds=91)
            await s.commit()
        class Recovered(Fetcher):
            async def fetch(self, url):
                return FetchResult(url=url, ok=True, status=200, body=b"<p>Recovered</p>",
                                   text="<p>Recovered</p>", content_type="text/html")
        def recovery_builder(settings, db):
            f = Recovered()
            return Crawler(settings, db, f, KeywordScorer([]), CompliancePolicy()), f
        await execute(db, settings, await claim(db), recovery_builder)
        result = (await c.get("/collection/jobs")).json()["jobs"][0]
        assert result["last_result"]["crawled"] == 1


def test_quoted_source_url_cannot_escape_page_handler():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the browser handler regression")
    source = (Path(__file__).parents[1]/"src/umbra/api/static/index.html").read_text(encoding="utf-8")
    helper = re.search(r"function attributeURL[^\n]+", source)[0]
    malicious = "https://fixture.example/');throw Error('injected');//"
    program = helper + "\nconst url=" + json.dumps(malicious) + """; let seen;
    const handler = "openPage('" + attributeURL(url) + "')";
    new Function('openPage', handler)(value => {seen=value});
    if(decodeURIComponent(seen)!==url) throw Error('URL did not round trip');
    """
    result = subprocess.run([node, "-e", program], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
