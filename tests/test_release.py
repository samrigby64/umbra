"""Commercial reliability regressions using isolated databases and synthetic pages."""
import asyncio
import datetime as dt
import hashlib
import io
import json
import sys
import time
import zipfile

import httpx
import pytest
import sqlalchemy as sa

from umbra.api.app import create_app
from umbra.compliance.policy import CompliancePolicy
from umbra.config import Settings
from umbra.crawl.crawler import Crawler
from umbra.crawl.scheduler import Scheduler, CrawlItem
from umbra.crawl.scorer import KeywordScorer
from umbra.db import Database
from umbra.evidence import build_bundle
from umbra.evaluation import evaluate
from umbra.fetch.client import TorFetcher
from umbra.intel.embeddings import HashingEmbedder, search, exact_search, to_bytes
from umbra.intel.entities import resolve_actors
from umbra.models import (
    ActorIdentifier, ApiKey, CaseItem, Embedding, Event, Ioc, Page, PageVersion,
    RelationshipReview, utcnow,
)
from umbra.relationships import pair_key, relationship_rows
from umbra.reprocess import embedding_coverage
from umbra.retention import purge_expired
from umbra.scope import ScopeError, allows


def config(tmp_path, **kwargs):
    return Settings(_env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path/'release.db'}",
                    embedder_kind="hashing", embedding_dim=64, **kwargs)


def captured(text="first\nversion", url="http://demo.onion/", **kwargs):
    body = text.encode()
    values = dict(url=url, hostname=url.split('/')[2], status="crawled", content=text,
                  raw_body=body, body_truncated=False, final_url=url,
                  content_sha256=hashlib.sha256(body).hexdigest(), content_length=len(body),
                  fetched_at=utcnow(), http_status=200, depth=0, score=1,
                  blocked=False, stored_content=True)
    values.update(kwargs)
    return Page(**values)


async def setup(tmp_path, **kwargs):
    settings = config(tmp_path, **kwargs)
    db = Database(settings.database_url)
    await db.create_all()
    return settings, db, Scheduler(db, settings)


async def test_claims_and_domain_caps_across_independent_instances(tmp_path):
    settings, db, first = await setup(tmp_path, max_pages_per_domain=12)
    other_db = Database(settings.database_url)
    second = Scheduler(other_db, settings)
    batch = [CrawlItem(f"http://demo.onion/{i}") for i in range(25)]
    counts = await asyncio.gather(first.add_many(batch), second.add_many(batch))
    assert sum(counts) == 12
    claimed = await asyncio.gather(*[s.claim() for s in [first, second]*8])
    urls = [c.url for c in claimed if c]
    assert len(urls) == len(set(urls)) == 12
    await other_db.dispose()
    await db.dispose()


async def test_real_process_crash_reclaim_and_stale_completion(tmp_path):
    settings, db, scheduler = await setup(tmp_path, reclaim_after_s=1)
    await scheduler.add(CrawlItem("http://demo.onion/"))
    code = '''import asyncio, sys
from umbra.db import Database
from umbra.config import Settings
from umbra.crawl.scheduler import Scheduler
async def main():
 d=Database(sys.argv[1]); s=Scheduler(d,Settings(_env_file=None))
 item=await s.claim(); print(item.claim_token,flush=True)
 await asyncio.sleep(60)
asyncio.run(main())
'''
    child = await asyncio.create_subprocess_exec(sys.executable, "-c", code,
        settings.database_url, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        token = int(await asyncio.wait_for(child.stdout.readline(), timeout=15))
    finally:
        child.kill()
        await child.wait()
    async with db.write_session() as s:
        await s.execute(sa.update(Page).values(claimed_at=utcnow()-dt.timedelta(seconds=10)))
        await s.commit()
    replacement = await scheduler.claim()
    assert replacement.claim_token > token
    assert await scheduler.complete(captured("stale"), [], claim_token=token) is None
    assert await scheduler.complete(captured("new owner"), [], claim_token=replacement.claim_token)
    assert await scheduler.complete(captured("duplicate"), [], claim_token=replacement.claim_token) is None
    await db.dispose()


async def test_heartbeat_prevents_reclaim(tmp_path):
    settings, db, scheduler = await setup(tmp_path, reclaim_after_s=1)
    await scheduler.add(CrawlItem("http://demo.onion/"))
    item = await scheduler.claim()
    async with db.write_session() as s:
        await s.execute(sa.update(Page).values(claimed_at=utcnow()-dt.timedelta(seconds=10)))
        await s.commit()
    assert await scheduler.heartbeat(item)
    assert await Scheduler(db, settings).claim() is None
    await db.dispose()


async def test_scope_and_depth_filter_existing_queue(tmp_path):
    settings, db, scheduler = await setup(tmp_path)
    await scheduler.add_many([CrawlItem("http://demo.onion/"),
                              CrawlItem("http://demo.onion/deep", depth=3),
                              CrawlItem("http://outside.onion/")])
    settings.allowed_hosts, settings.max_depth = ["demo.onion"], 0
    assert (await scheduler.claim()).url == "http://demo.onion/"
    assert await scheduler.claim() is None
    assert not await scheduler.add(CrawlItem("http://outside.onion/other"))
    assert not allows("http://demo.onion.evil.example/", ["demo.onion"])
    with pytest.raises(ScopeError):
        allows("http://demo.onion@outside.onion/", ["demo.onion"])
    await db.dispose()


async def transport_fetcher(monkeypatch, handler, **kwargs):
    import umbra.fetch.client as module
    async def no_network_guard(request):
        pass
    monkeypatch.setattr(module, "guard_request", no_network_guard)
    fetcher = TorFetcher("127.0.0.1", 9050, user_agent="test", use_tor=False, **kwargs)
    hooks = fetcher._client.event_hooks
    await fetcher._client.aclose()
    fetcher._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
        event_hooks=hooks, follow_redirects=True)
    return fetcher


async def test_redirect_is_rejected_before_outside_request(monkeypatch):
    visited = []
    def handler(request):
        visited.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://outside.onion/"})
    fetcher = await transport_fetcher(monkeypatch, handler, allowed_hosts=["demo.onion"])
    with pytest.raises(ScopeError):
        await fetcher.fetch("http://demo.onion/")
    assert visited == ["http://demo.onion/"]
    await fetcher.aclose()


@pytest.mark.parametrize("size,truncated", [(7, False), (8, False), (9, True), (100_000, True)])
async def test_download_limit_and_truncation(monkeypatch, size, truncated):
    fetcher = await transport_fetcher(monkeypatch, lambda r: httpx.Response(
        200, content=b"x"*size, headers={"content-type": "text/plain"}), max_bytes=8)
    result = await fetcher.fetch("http://demo.onion/")
    assert len(result.body) == min(size, 8)
    assert result.text.encode() == result.body and result.truncated == truncated
    await fetcher.aclose()


async def test_versions_bytes_diffs_failure_timestamp_and_policy_removal(tmp_path):
    _, db, scheduler = await setup(tmp_path)
    original = captured("caf\xe9\nfirst", raw_body=b"caf\xe9\nfirst",
                         content_sha256=hashlib.sha256(b"caf\xe9\nfirst").hexdigest())
    await scheduler.complete(original, [])
    await scheduler.complete(captured("second\nversion", body_truncated=True), [])
    async with db.session() as s:
        versions = (await s.execute(sa.select(PageVersion).order_by(PageVersion.id))).scalars().all()
    from umbra.versions import compare
    assert "-café" in compare(*versions)["diff"]
    bundle, summary = await build_bundle(db, version_ids=[versions[0].id])
    archive = zipfile.ZipFile(io.BytesIO(bundle))
    item = json.loads(archive.read("manifest.json"))["items"][0]
    assert archive.read(item["included"]["body_file"]) == b"caf\xe9\nfirst"
    assert item["body_verifiable"] and item["complete_body_verifiable"]
    assert summary["verifiable_bodies"] == 1
    bundle, _ = await build_bundle(db)
    item = json.loads(zipfile.ZipFile(io.BytesIO(bundle)).read("manifest.json"))["items"][0]
    assert item["body_verifiable"] and not item["complete_body_verifiable"]
    capture_time = item["capture"]["fetched_at"]
    await scheduler.complete(captured(status="dead", content=None, raw_body=None), [])
    bundle, _ = await build_bundle(db)
    item = json.loads(zipfile.ZipFile(io.BytesIO(bundle)).read("manifest.json"))["items"][0]
    assert item["capture"]["fetched_at"] == capture_time
    await scheduler.complete(captured("second\nversion", blocked=True, status="blocked",
                                     content=None, raw_body=None, stored_content=False), [])
    async with db.session() as s:
        assert await s.scalar(sa.select(sa.func.count()).select_from(PageVersion)) == 0
        assert (await s.get(Page, "http://demo.onion/")).raw_body is None
    await db.dispose()


async def test_case_versions_pinned_against_rolling_limit_but_retention_removes(tmp_path):
    _, db, scheduler = await setup(tmp_path, versions_per_page=1)
    await scheduler.complete(captured("one"), [])
    async with db.write_session() as s:
        version = await s.scalar(sa.select(PageVersion.id))
        s.add(CaseItem(case_id=1, page_url="http://demo.onion/", version_id=version))
        await s.commit()
    for text in ["two", "three"]:
        await scheduler.complete(captured(text), [])
    async with db.session() as s:
        versions = (await s.execute(sa.select(PageVersion.id))).scalars().all()
        assert len(versions) == 2 and version in versions
    async with db.write_session() as s:
        await s.execute(sa.update(Page).values(created_at=utcnow()-dt.timedelta(days=40)))
        await s.commit()
    await purge_expired(db, 30)
    async with db.session() as s:
        assert await s.scalar(sa.select(sa.func.count()).select_from(PageVersion)) == 0
    await db.dispose()


async def test_search_same_dimension_different_model_and_exact_identifier(tmp_path):
    _, db, _ = await setup(tmp_path)
    embedder = HashingEmbedder(64)
    async with db.write_session() as s:
        for name, model in [("good", embedder.name), ("wrong", "different-model")]:
            url = f"http://demo.onion/{name}"
            s.add(captured("notebook", url=url))
            s.add(Embedding(page_url=url, model=model, dim=64, vector=to_bytes(embedder.embed("notebook"))))
        s.add(Ioc(page_url="http://demo.onion/good", ioc_type="handle", value="ExampleSeller"))
        await s.commit()
    found = await search(db, embedder, "notebook")
    assert [r["url"] for r in found] == ["http://demo.onion/good"]
    coverage = await embedding_coverage(db, embedder)
    assert coverage["stale"] == 1 and coverage["searchable_now"] == 1
    assert len(await exact_search(db, "ExampleSeller")) == 1
    assert await exact_search(db, "Example") == []
    await db.dispose()


async def test_case_api_workflow_review_export_auth_and_diff(tmp_path):
    settings, db, scheduler = await setup(tmp_path)
    await scheduler.complete(captured(), [])
    await scheduler.complete(captured("changed\ntext"), [])
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        case = (await c.post("/cases", json={"name":"Test case", "assigned_to":"Test analyst"})).json()
        versions = (await c.get("/versions", params={"url":"http://demo.onion/"})).json()["versions"]
        saved = await c.post(f"/cases/{case['id']}/items", json={"version_id":versions[0]["id"],
                               "notes":"Reviewed source", "verdict":"relevant"})
        assert saved.status_code == 200
        diff = await c.get("/versions/compare", params={"before":versions[1]["id"], "after":versions[0]["id"]})
        assert "+changed" in diff.json()["diff"]
        exported = await c.get(f"/cases/{case['id']}/export")
        assert exported.status_code == 200
        details = (await c.get(f"/cases/{case['id']}")).json()
        assert details["activity"][0]["action"] == "exported"
        assert hashlib.sha256(exported.content).hexdigest() in details["activity"][0]["detail"]
        async with db.write_session() as s:
            s.add(ApiKey(key="test-viewer", name="viewer", role="viewer"))
            await s.commit()
        assert (await c.get("/cases")).status_code == 401
        assert (await c.post("/cases", json={"name":"denied"}, headers={"X-API-Key":"test-viewer"})).status_code == 403
        assert (await c.get("/cases", headers={"X-API-Key":"test-viewer"})).status_code == 200
    await db.dispose()


async def test_rejected_relationship_prevents_indirect_merge_and_survives_rebuild(tmp_path):
    _, db, _ = await setup(tmp_path)
    async with db.write_session() as s:
        for url, names in [("http://a.onion/",["A","B"]),("http://b.onion/",["B","C"])]:
            for name in names:
                s.add(Ioc(page_url=url, ioc_type="handle", value=name, context="Fixture source"))
        s.add(RelationshipReview(pair_key=pair_key(("handle","A"),("handle","C")),
            left_type="handle",left_value="A",right_type="handle",right_value="C",
            verdict="rejected",reason="Different synthetic operators",reviewer="test"))
        await s.commit()
    for _ in range(2):
        await resolve_actors(db)
    async with db.session() as s:
        rows = (await s.execute(sa.select(ActorIdentifier))).scalars().all()
        mapping = {r.value:r.actor_id for r in rows}
        assert mapping.get("A") != mapping.get("C")
        assert await s.scalar(sa.select(sa.func.count()).select_from(RelationshipReview)) == 1
    relationships = await relationship_rows(db)
    assert any(r["verdict"] == "rejected" for r in relationships["relationships"])
    await db.dispose()


async def test_processing_failure_cap_does_not_emit_outages(tmp_path):
    _, db, scheduler = await setup(tmp_path, max_fetch_failures=2)
    await scheduler.add(CrawlItem("http://demo.onion/"))
    for _ in range(2):
        async with db.write_session() as s:
            await s.execute(sa.update(Page).values(next_crawl_at=utcnow()))
            await s.commit()
        item = await scheduler.claim()
        await scheduler.release(item, "Parser error")
    async with db.session() as s:
        row = await s.get(Page,"http://demo.onion/")
        assert row.status == "error" and row.next_crawl_at is None
        assert row.processing_failures == 2 and row.consecutive_failures == 0
        assert await s.scalar(sa.select(sa.func.count()).select_from(Event)) == 0
    await db.dispose()


async def test_compute_does_not_block_network_loop_and_cancel_releases_claim(tmp_path):
    settings, db, _ = await setup(tmp_path, max_workers=1)
    entered = asyncio.Event()
    class WaitingFetcher:
        async def fetch(self, url):
            entered.set()
            await asyncio.Event().wait()
    crawler = Crawler(settings, db, WaitingFetcher(), KeywordScorer([]), CompliancePolicy())
    task = asyncio.create_task(crawler.run(["http://demo.onion/"]))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with db.session() as s:
        assert (await s.get(Page,"http://demo.onion/")).status != "in_progress"
    computing = asyncio.create_task(crawler._compute(time.sleep, 0.2))
    await asyncio.sleep(0.02)
    assert not computing.done()
    await computing
    await db.dispose()


async def test_labelled_evaluation_reports_false_positive_examples():
    report = await evaluate()
    assert report["sample_count"] >= 14
    assert report["metrics"]["listings"]["false_positive"] >= 1
    assert "not an estimate" in report["notice"]


async def test_trickling_response_has_total_deadline(monkeypatch):
    class Trickle(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.01)
                yield b"x"
    fetcher = await transport_fetcher(monkeypatch, lambda r: httpx.Response(
        200, stream=Trickle()), retries=0, timeout=0.05)
    result = await asyncio.wait_for(fetcher.fetch("http://demo.onion/"), 1)
    assert not result.ok and "TimeoutError" in result.error
    await fetcher.aclose()


async def test_live_run_not_reaped_by_another_worker(tmp_path):
    from umbra.runs import record_run, reap_abandoned_runs
    _, db, _ = await setup(tmp_path)
    async with record_run(db):
        assert await reap_abandoned_runs(db) == 0
    await db.dispose()


async def test_force_seed_resets_depth_and_exact_success_budget(tmp_path):
    from umbra.fetch.client import FetchResult
    settings, db, scheduler = await setup(tmp_path, max_pages=2, max_workers=8)
    await scheduler.add_many([CrawlItem(f"http://demo.onion/{i}", depth=4) for i in range(10)])
    settings.max_depth = 0
    class Success:
        async def fetch(self, url):
            await asyncio.sleep(0.01)
            return FetchResult(url=url, ok=True, status=200, body=b"hello",text="hello")
    crawler = Crawler(settings, db, Success(), KeywordScorer([]), CompliancePolicy())
    stats = await crawler.run([f"http://demo.onion/{i}" for i in range(10)], force_seeds=True)
    assert stats["crawled"] == 2
    assert (await scheduler.counts())["discovered"] == 8
    await db.dispose()


async def test_scope_preview_validates_inputs_without_starting_crawl(tmp_path):
    settings, db, _ = await setup(tmp_path)
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as c:
        response = await c.post("/admin/crawl-preview",json={"seeds":["http://demo.onion/"],
            "strict_scope":True,"max_depth":0,"max_pages":10})
        assert response.json()["allowed_hosts"] == ["demo.onion"]
        assert response.json()["max_depth"] == 0
        assert not (await c.get("/admin/crawl-status")).json()["running"]
        for payload in [{"seeds":"wrong"},{"seeds":["http://[dot]/"]},
                        {"seeds":["http://demo.onion/"],"max_depth":-1}]:
            assert (await c.post("/admin/crawl-preview",json=payload)).status_code == 400
    await db.dispose()


async def test_upgrade_preserves_legacy_page_and_does_not_invent_capture(tmp_path):
    settings = config(tmp_path)
    db = Database(settings.database_url)
    old = Page.__table__.to_metadata(sa.MetaData())
    for name in ("raw_body", "body_truncated", "final_url", "content_captured_at", "processing_failures"):
        old._columns.remove(old.c[name])
    async with db._engine.begin() as connection:
        await connection.run_sync(old.create)
        await connection.execute(sa.insert(old).values(url="http://legacy.onion/",
            content="Legacy evidence", content_sha256="abc", status="crawled"))
    await db.create_all()
    assert await db.upgrade_schema() == []
    async with db.session() as s:
        page = await s.get(Page,"http://legacy.onion/")
        assert page.content == "Legacy evidence" and page.raw_body is None
        from umbra.versions import snapshot
        version = snapshot(page,legacy=True)
        assert version.captured_at is None and version.body_truncated is None
    await db.dispose()


async def test_removed_version_id_never_reused(tmp_path):
    _, db, scheduler = await setup(tmp_path)
    await scheduler.complete(captured("first"), [])
    async with db.write_session() as s:
        old = await s.scalar(sa.select(PageVersion.id))
        s.add(CaseItem(case_id=1, version_id=old, page_url="http://demo.onion/"))
        await s.execute(sa.delete(PageVersion))
        await s.commit()
    await scheduler.complete(captured("replacement"), [])
    async with db.session() as s:
        assert await s.get(PageVersion,old) is None
        assert await s.scalar(sa.select(PageVersion.id)) > old
    await db.dispose()


async def test_simultaneous_runs_only_count_their_own_events(tmp_path):
    from umbra.runs import record_run, list_runs
    _, db, _ = await setup(tmp_path)
    arrived = 0
    ready = asyncio.Event()
    async def collect(n):
        nonlocal arrived
        async with record_run(db) as run:
            arrived += 1
            if arrived == 2:
                ready.set()
            await ready.wait()
            async with db.session() as s:
                s.add_all([Event(kind="page_new", summary=f"Fixture {n}") for _ in range(n)])
                await s.commit()
            run.pages_crawled = n
    await asyncio.gather(collect(2), collect(3))
    rows = await list_runs(db)
    assert {r["events_emitted"] for r in rows} == {2,3}
    assert all(r["events_emitted"] == r["pages_crawled"] for r in rows)
    await db.dispose()


async def test_extraction_snippets_retain_the_matched_identifier_and_price():
    from umbra.crawl.parse import parse_page
    from umbra.enrich.ioc import IocExtractor
    from umbra.enrich.structured import ListingExtractor
    page = captured()
    parsed = parse_page("<p>Vendor: ExampleSeller</p><p>Notebook $12</p>", page.url)
    ioc = (await IocExtractor().enrich(page, parsed))[0]
    listing = (await ListingExtractor().enrich(page, parsed))[0]
    assert "ExampleSeller" in ioc.context
    assert "Notebook $12" in listing.context
