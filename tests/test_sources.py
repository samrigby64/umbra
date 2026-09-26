"""Tests for source packs — coverage as configuration.

Two things matter here. Packs must be loadable and seedable without a code
change, and generated packs must carry the evidence that justified each entry —
a seed list is a claim about the world, and one without provenance cannot be
audited or pruned when it goes stale.
"""

import datetime as dt
import json

import sqlalchemy as sa

from umbra.config import Settings
from umbra.db import Database
from umbra.models import STATUS_CRAWLED, Ioc, Listing, Page
from umbra.sourcegen import generate
from umbra.sources import available, get, seed_pack


def _write_pack(directory, name, sources, category="test"):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps({
        "name": name, "description": f"{name} pack", "category": category,
        "version": "2026-01-01",
        "sources": [{"url": u, "note": "n"} for u in sources],
    }), encoding="utf-8")


def test_operator_packs_load_alongside_bundled(tmp_path):
    _write_pack(tmp_path / "packs", "my-sector", ["http://a.onion/", "http://b.onion/"])
    packs = {p.name: p for p in available(tmp_path / "packs")}

    assert "my-sector" in packs
    assert packs["my-sector"].origin == "operator"
    assert packs["my-sector"].urls == ["http://a.onion/", "http://b.onion/"]
    assert any(p.origin == "bundled" for p in packs.values())  # shipped ones still there


def test_operator_pack_overrides_a_bundled_one_of_the_same_name(tmp_path):
    """A customer curating coverage for their sector must not have it silently
    replaced by a shipped default on upgrade."""
    bundled = get("getting-started")
    assert bundled is not None and bundled.origin == "bundled"  # the override is real

    _write_pack(tmp_path / "packs", "getting-started", ["http://mine.onion/"])
    pack = get("getting-started", tmp_path / "packs")
    assert pack.origin == "operator" and pack.urls == ["http://mine.onion/"]


def test_shipped_packs_contain_no_private_or_criminal_targets():
    """The public repo ships only the verified example pack. Real collection
    packs live in an operator directory and must never be bundled."""
    from umbra.sources import BUNDLED_DIR

    shipped = sorted(f.stem for f in BUNDLED_DIR.glob("*.json"))
    assert shipped == ["getting-started"]
    pack = get("getting-started")
    assert pack.sources and all(s.evidence and s.last_seen for s in pack.sources)


def test_malformed_pack_is_skipped_not_fatal(tmp_path):
    """One bad file in an operator directory must not take out source loading."""
    (tmp_path / "packs").mkdir()
    (tmp_path / "packs" / "broken.json").write_text("{not json", encoding="utf-8")
    _write_pack(tmp_path / "packs", "good", ["http://a.onion/"])

    names = {p.name for p in available(tmp_path / "packs")}
    assert "good" in names and "broken" not in names


async def test_seeding_a_pack_queues_its_sources(tmp_path):
    _write_pack(tmp_path / "packs", "tiny", ["http://a.onion/", "http://b.onion/"])
    settings = Settings()
    settings.database_url = f"sqlite+aiosqlite:///{tmp_path / 'seed.db'}"
    settings.source_packs_path = str(tmp_path / "packs")
    db = Database(settings.database_url)
    await db.create_all()

    result = await seed_pack(db, settings, "tiny")
    assert result == {"pack": "tiny", "sources": 2, "queued": 2}

    async with db.session() as s:
        urls = set((await s.execute(sa.select(Page.url))).scalars())
    assert urls == {"http://a.onion/", "http://b.onion/"}

    # re-seeding is not an error and does not duplicate the frontier
    assert (await seed_pack(db, settings, "tiny"))["queued"] == 0
    await db.dispose()


async def test_generated_packs_carry_their_evidence(tmp_path):
    """A generated pack must say why each host is in it — without that, nobody
    can tell a verified source from a guess, which is the whole risk."""
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'gen.db'}")
    await db.create_all()
    now = dt.datetime.now(dt.timezone.utc)
    async with db.session() as s:
        s.add_all([
            Page(url="http://shop.onion/", hostname="shop.onion", status=STATUS_CRAWLED,
                 title="Shop", depth=0, score=1.0, content_sha256="a", fetched_at=now,
                 blocked=False, stored_content=True),
            Page(url="http://vend.onion/", hostname="vend.onion", status=STATUS_CRAWLED,
                 title="Vendor", depth=0, score=1.0, content_sha256="b", fetched_at=now,
                 blocked=False, stored_content=True),
        ])
        s.add_all([Listing(page_url="http://shop.onion/", price=1.0 + i, currency="USD")
                   for i in range(4)])
        s.add_all([
            Ioc(page_url="http://vend.onion/", ioc_type="pgp_fp", value="F" * 40),
            Ioc(page_url="http://vend.onion/", ioc_type="btc", value="ADDR1"),
        ])
        await s.commit()

    written = await generate(db, tmp_path / "out")
    assert written["commerce"] == 1 and written["actor-infrastructure"] == 1

    commerce = json.loads((tmp_path / "out" / "commerce.json").read_text(encoding="utf-8"))
    entry = commerce["sources"][0]
    assert entry["url"] == "http://shop.onion/"
    assert "listing" in entry["evidence"]
    assert entry["last_seen"] == now.date().isoformat()

    # and the description does not over-claim what the evidence supports
    assert "not" in commerce["description"] and "illegal" in commerce["description"]

    actors = json.loads((tmp_path / "out" / "actor-infrastructure.json").read_text(encoding="utf-8"))
    assert actors["sources"][0]["url"] == "http://vend.onion/"
    assert "identifier" in actors["sources"][0]["evidence"]
    await db.dispose()


def test_local_and_private_hosts_are_never_publishable():
    """A pack is shipped to someone else. Found live: a generated pack contained
    http://127.0.0.1/ from demo fixtures left in a working corpus."""
    from umbra.sourcegen import is_publishable

    for host in ("127.0.0.1", "127.0.0.1:8000", "localhost", "10.0.0.5", "192.168.1.10",
                 "172.16.0.1", "169.254.1.1", "::1", "[::1]:8000", "fe80::1",
                 "dev.local", "box.internal", ""):
        assert not is_publishable(host), host
    for host in ("abc.onion", "example.com", "8.8.8.8"):
        assert is_publishable(host), host


async def test_generated_packs_exclude_local_fixtures(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'local.db'}")
    await db.create_all()
    now = dt.datetime.now(dt.timezone.utc)
    async with db.session() as s:
        s.add_all([
            Page(url="http://127.0.0.1:8000/market", hostname="127.0.0.1",
                 status=STATUS_CRAWLED, depth=0, score=1.0, content_sha256="a",
                 fetched_at=now, blocked=False, stored_content=True),
            Page(url="http://real.onion/", hostname="real.onion", status=STATUS_CRAWLED,
                 depth=0, score=1.0, content_sha256="b", fetched_at=now,
                 blocked=False, stored_content=True),
        ])
        s.add_all([Listing(page_url="http://127.0.0.1:8000/market", price=1.0 + i,
                           currency="USD") for i in range(5)])
        await s.commit()

    await generate(db, tmp_path / "out")
    for name in ("commerce", "verified-live"):
        pack = json.loads((tmp_path / "out" / f"{name}.json").read_text(encoding="utf-8"))
        assert not any("127.0.0.1" in s["url"] for s in pack["sources"]), name
    await db.dispose()


async def test_generated_packs_only_contain_hosts_that_answered(tmp_path):
    """Dead hosts must never be promoted into coverage — that is how a seed list
    silently becomes a budget sink."""
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'dead.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add(Page(url="http://gone.onion/", hostname="gone.onion", status="dead",
                   depth=0, score=1.0, blocked=False, stored_content=False))
        await s.commit()

    written = await generate(db, tmp_path / "out")
    assert written["verified-live"] == 0
    await db.dispose()
