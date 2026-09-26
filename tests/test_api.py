"""API + watchlist alerting integration test (ASGI transport, no live server)."""

import httpx
from httpx import ASGITransport

from umbra.api import create_app
from umbra.config import Settings
from umbra.db import Database
from umbra.intel.embeddings import HashingEmbedder, to_bytes
from umbra.intel.entities import STRONG_TYPES
from umbra.models import ApiKey, Embedding, Ioc, Page


async def _seed(url: str) -> Settings:
    settings = Settings()
    settings.database_url = url
    # Pin the hashing embedder: tests must not depend on downloading a model, and
    # the seeded vectors below have to match the dimension the app will query with.
    settings.embedder_kind = "hashing"
    settings.embedding_dim = 256
    db = Database(url)
    await db.create_all()
    async with db.session() as s:
        s.add(Page(
            url="http://x.onion/", hostname="x.onion", status="crawled",
            title="Vendor Market", page_type="marketplace",
            content="bitcoin vendor market listings", blocked=False, stored_content=True,
        ))
        s.add(Ioc(page_url="http://x.onion/", ioc_type="btc", value="ADDR1"))
        s.add(Embedding(
            page_url="http://x.onion/", model="hashing-256", dim=256,
            vector=to_bytes(HashingEmbedder(256).embed("bitcoin vendor market listings")),
        ))
        await s.commit()
    await db.dispose()
    return settings


async def test_api_endpoints_and_alerting(tmp_path):
    settings = await _seed(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}")
    app = create_app(settings)
    transport = ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        assert (await c.get("/health")).json()["status"] == "ok"

        # the GUI shell is served at /
        ui = await c.get("/")
        assert ui.status_code == 200 and "UMBRA" in ui.text

        # crawl-control endpoint is wired
        assert (await c.get("/admin/crawl-status")).json()["running"] is False

        stats = (await c.get("/stats")).json()
        assert stats["iocs"] == 1

        pages = (await c.get("/pages", params={"page_type": "marketplace"})).json()["pages"]
        assert len(pages) == 1 and pages[0]["url"] == "http://x.onion/"

        results = (await c.get("/search", params={"q": "bitcoin market"})).json()["results"]
        assert results and results[0]["url"] == "http://x.onion/"

        # watchlist -> evaluate -> alert
        wl = (await c.post("/watchlists", json={"kind": "keyword", "value": "bitcoin"})).json()
        assert wl["id"]
        ev = (await c.post("/watchlists/evaluate")).json()
        assert ev["new_alerts"] >= 1
        alerts = (await c.get("/alerts")).json()["alerts"]
        assert any(a["page_url"] == "http://x.onion/" for a in alerts)


async def test_webhook_to_private_network_is_rejected_at_creation(tmp_path):
    """The server POSTs collected intelligence to this URL from inside the
    deployment's network. A watchlist is the one place a caller gets to choose
    where the server connects to, so it is checked before it is saved."""
    import sqlalchemy as sa
    from umbra.models import Watchlist

    url = f"sqlite+aiosqlite:///{tmp_path / 'wh.db'}"
    settings = await _seed(url)
    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        for bad in (
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://127.0.0.1:9050/",                    # the Tor control side
            "http://[::1]:8000/admin/crawl",             # ourselves
            "file:///etc/passwd",
        ):
            r = await c.post(
                "/watchlists", json={"kind": "keyword", "value": "acme", "webhook_url": bad}
            )
            assert r.status_code == 400 and "rejected" in r.json()["detail"], bad

    db = Database(url)
    async with db.session() as s:
        saved = (await s.execute(sa.select(sa.func.count()).select_from(Watchlist))).scalar()
    assert saved == 0  # nothing slipped through
    await db.dispose()


async def test_public_bind_never_runs_open(tmp_path):
    """Bound to a non-loopback address with no key: mint one rather than expose
    an unauthenticated admin API to the network."""
    import sqlalchemy as sa

    url = f"sqlite+aiosqlite:///{tmp_path / 'pub.db'}"
    settings = await _seed(url)
    app = create_app(settings, public=True)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/stats")).status_code == 401  # no longer open

    db = Database(url)
    async with db.session() as s:
        keys = (await s.execute(sa.select(ApiKey))).scalars().all()
    assert len(keys) == 1
    assert keys[0].role == "admin" and keys[0].name == "bootstrap-admin"

    # the minted key works, and a restart does not mint a second one
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers={"X-API-Key": keys[0].key},
        ) as c:
            assert (await c.get("/stats")).status_code == 200
    async with db.session() as s:
        assert (await s.execute(sa.select(sa.func.count()).select_from(ApiKey))).scalar() == 1
    await db.dispose()


async def test_loopback_bind_stays_open_for_local_dev(tmp_path):
    settings = await _seed(f"sqlite+aiosqlite:///{tmp_path / 'loop.db'}")
    app = create_app(settings)  # public=False: the local-dev convenience is kept
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/stats")).status_code == 200


async def test_stale_embeddings_are_explained_and_repairable(tmp_path):
    """Changing the embedder makes old vectors invisible, not wrong — search goes
    quietly empty. That must be reported, and fixable without re-crawling."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'stale.db'}"
    settings = await _seed(url)
    # the corpus was embedded at dim 256; the service now runs a different width
    settings.embedding_dim = 512

    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        first = (await c.get("/search", params={"q": "bitcoin vendor market"})).json()
        assert first["results"] == []
        assert "warning" in first  # not silently empty
        assert first["coverage"]["searchable_now"] == 0
        assert first["coverage"]["stale"] == 1

        rebuilt = (await c.post("/admin/reembed")).json()
        assert rebuilt["pages"] == 1 and rebuilt["dim"] == 512

        after = (await c.get("/search", params={"q": "bitcoin vendor market"})).json()
        assert [r["url"] for r in after["results"]] == ["http://x.onion/"]
        assert "warning" not in after

        coverage = (await c.get("/embeddings/coverage")).json()
        assert coverage["searchable_now"] == 1 and coverage["stale"] == 0


async def test_ioc_type_filter_single_set_and_actor(tmp_path):
    """The Indicators view is unusable unfiltered — onion links swamp everything."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'filter.db'}"
    settings = await _seed(url)
    db = Database(url)
    async with db.session() as s:
        s.add_all([
            Ioc(page_url="http://x.onion/", ioc_type="onion", value="aaa.onion"),
            Ioc(page_url="http://x.onion/", ioc_type="pgp_fp", value="F" * 40),
            Ioc(page_url="http://x.onion/", ioc_type="email", value="victim@acme.com"),
        ])
        await s.commit()
    await db.dispose()

    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        one = (await c.get("/iocs", params={"type": "onion"})).json()["iocs"]
        assert {i["type"] for i in one} == {"onion"}

        several = (await c.get("/iocs", params={"type": "onion,pgp_fp"})).json()["iocs"]
        assert {i["type"] for i in several} == {"onion", "pgp_fp"}

        # 'actor' resolves to STRONG_TYPES: identifiers only, victim email excluded
        actor = (await c.get("/iocs", params={"type": "actor"})).json()["iocs"]
        kinds = {i["type"] for i in actor}
        assert "pgp_fp" in kinds and "onion" not in kinds and "email" not in kinds

        # the CSV export honours the same filter
        csv_text = (await c.get("/export/iocs.csv", params={"type": "actor"})).text
        assert "F" * 40 in csv_text and "victim@acme.com" not in csv_text

        # distinct=true: one row per value with a page count, most-seen first.
        # Without it a capped list fills with repeats and rare types vanish.
        db2 = Database(url)
        async with db2.session() as s:
            s.add_all([Ioc(page_url=f"http://p{i}.onion/", ioc_type="btc", value="ADDR1")
                       for i in range(3)])
            await s.commit()
        await db2.dispose()
        distinct = (await c.get("/iocs", params={"type": "actor", "distinct": "true"})).json()["iocs"]
        by_value = {i["value"]: i for i in distinct}
        assert by_value["ADDR1"]["pages"] == 4          # seeded once + 3 more sightings
        assert distinct[0]["value"] == "ADDR1"          # most-seen first
        assert sum(1 for i in distinct if i["value"] == "ADDR1") == 1
        # the type filter must hold in distinct mode too — the first version of
        # this test only counted rows and would have passed with onion links in
        assert {i["type"] for i in distinct} <= set(STRONG_TYPES)
        assert not any(i["type"] in ("onion", "email") for i in distinct)

        # and the GUI is served uncached, so an upgrade shows up on plain reload
        assert (await c.get("/")).headers.get("cache-control") == "no-store"


async def test_sites_queue_and_export(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'sites.db'}"
    settings = await _seed(url)
    # add a queued (never-fetched) link on a second host
    db = Database(url)
    async with db.session() as s:
        s.add(Page(url="http://y.onion/a", hostname="y.onion", status="discovered",
                   blocked=False, stored_content=False))
        await s.commit()
    await db.dispose()

    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        sites = (await c.get("/sites")).json()["sites"]
        by_host = {s["host"]: s for s in sites}
        assert by_host["x.onion"]["crawled"] == 1 and by_host["x.onion"]["iocs"] == 1
        assert by_host["y.onion"]["queued"] == 1 and by_host["y.onion"]["crawled"] == 0
        assert by_host["x.onion"]["pinned"] is False  # nothing pinned yet: no marker

        # CSV export of indicators
        csv_resp = await c.get("/export/iocs.csv")
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]
        assert "type,value,page_url" in csv_resp.text and "ADDR1" in csv_resp.text

        # clearing the queue drops only the never-fetched link
        assert (await c.request("DELETE", "/admin/queue")).json()["removed"] == 1
        assert (await c.get("/overview")).json()["counts"]["queued"] == 0
        assert (await c.get("/overview")).json()["counts"]["pages"] == 1  # crawled page kept

        # stopping when nothing is running is a clean 409, not a crash
        assert (await c.post("/admin/crawl/stop")).status_code == 409


async def test_api_key_gating(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}"
    settings = await _seed(url)

    # No keys yet -> open. Add a key -> now required.
    db = Database(url)
    async with db.session() as s:
        s.add(ApiKey(key="secret-key", name="test"))
        await s.commit()
    await db.dispose()

    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get("/stats")).status_code == 401
        assert (await c.get("/stats", headers={"X-API-Key": "wrong"})).status_code == 401
        assert (await c.get("/stats", headers={"X-API-Key": "secret-key"})).status_code == 200


async def test_rbac_viewer_cannot_manage(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'rbac.db'}"
    settings = await _seed(url)
    db = Database(url)
    async with db.session() as s:
        s.add(ApiKey(key="viewer-key", name="v", role="viewer"))
        s.add(ApiKey(key="admin-key", name="a", role="admin"))
        await s.commit()
    await db.dispose()

    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        # viewer: reads OK, management forbidden
        assert (await c.get("/stats", headers={"X-API-Key": "viewer-key"})).status_code == 200
        r = await c.post(
            "/watchlists", json={"kind": "keyword", "value": "x"},
            headers={"X-API-Key": "viewer-key"},
        )
        assert r.status_code == 403
        # admin: management allowed
        r = await c.post(
            "/watchlists", json={"kind": "keyword", "value": "x"},
            headers={"X-API-Key": "admin-key"},
        )
        assert r.status_code == 200


async def test_counts_include_services_that_went_dark_but_kept_their_content(tmp_path):
    """A failed recrawl leaves the page "crawled" (content retained) with a raised
    failure count. The Overview card and the Sites column both counted only
    status == "dead", so a market that had just gone dark read as 0 unreachable."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'dark.db'}"
    settings = await _seed(url)
    db = Database(url)
    async with db.session() as s:
        s.add(Page(url="http://gone.onion/", hostname="gone.onion", status="crawled",
                   content="archived listing text", content_sha256="s", blocked=False,
                   stored_content=True, consecutive_failures=2))
        await s.commit()
    await db.dispose()

    app = create_app(settings)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        counts = (await c.get("/overview")).json()["counts"]
        assert counts["unreachable"] == 1
        assert counts["pages"] == 2          # its archived content is still counted as stored
        sites = {x["host"]: x for x in (await c.get("/sites")).json()["sites"]}
        assert sites["gone.onion"]["unreachable"] == 1
        assert sites["x.onion"]["unreachable"] == 0
