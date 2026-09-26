"""Tests for structured extractors, entity resolution, and the semantic scorer."""

import hashlib

import pytest
import sqlalchemy as sa

from umbra.config import Settings
from umbra.crawl.parse import DiscoveredLink, ParsedPage
from umbra.crawl.scorer import EmbeddingScorer
from umbra.db import Database
from umbra.enrich.structured import CredentialExtractor, ListingExtractor
from umbra.intel.embeddings import HashingEmbedder, build_embedder
from umbra.intel.entities import resolve_actors
from umbra.models import Actor, ActorIdentifier, Ioc, Page


def test_build_embedder_graceful_fallback(monkeypatch):
    settings = Settings()
    settings.embedder_kind = "hashing"
    assert isinstance(build_embedder(settings), HashingEmbedder)

    # 'local' requested but unavailable (extra not installed, or the model can't
    # be downloaded) -> falls back to hashing rather than taking search down
    def boom(*_args, **_kwargs):
        raise RuntimeError("fastembed missing")

    monkeypatch.setattr("umbra.intel.embeddings.LocalEmbedder", boom)
    settings.embedder_kind = "local"
    assert isinstance(build_embedder(settings), HashingEmbedder)

    # unknown kind is a hard error
    settings.embedder_kind = "bogus"
    with pytest.raises(ValueError):
        build_embedder(settings)


def test_hashing_dim_default_is_large_enough_to_be_useful():
    """256 buckets put ~32 distinct words of a real corpus into each bucket,
    which collapsed unrelated pages onto identical vectors."""
    assert Settings().embedding_dim >= 2048


async def test_credential_extractor_hashes_passwords():
    parsed = ParsedPage(
        url="http://x.onion/",
        text="combolist: alice@corp.com:hunter2 and bob@evil.org:pw123456 dumped",
    )
    creds = await CredentialExtractor().enrich(Page(url="http://x.onion/"), parsed)
    by_email = {c.email: c for c in creds}

    assert "alice@corp.com" in by_email
    assert by_email["alice@corp.com"].domain == "corp.com"
    # plaintext is never stored — only the SHA-256
    assert by_email["alice@corp.com"].password_sha256 == hashlib.sha256(b"hunter2").hexdigest()
    assert not hasattr(by_email["alice@corp.com"], "password")


async def test_listing_extractor_finds_prices_and_context():
    parsed = ParsedPage(
        url="http://x.onion/", text="Cocaine 5g premium $120 then Heroin 2g at 0.004 BTC"
    )
    listings = await ListingExtractor().enrich(Page(url="http://x.onion/"), parsed)
    prices = {(round(x.price, 4), x.currency) for x in listings}

    assert (120.0, "USD") in prices
    assert (0.004, "BTC") in prices
    assert any("Cocaine" in (x.product or "") for x in listings)


async def test_listing_extractor_ignores_range_bounds():
    """Real text from a crawled carding market. Only the asking price is a price —
    the 1000/5000 describe the goods and used to produce phantom listings."""
    parsed = ParsedPage(
        url="http://x.onion/",
        text="Price Quantity 10 x cards with credit from 1000 to 5000 USD $90 Sold out",
    )
    listings = await ListingExtractor().enrich(Page(url="http://x.onion/"), parsed)
    prices = {(x.price, x.currency) for x in listings}

    assert (90.0, "USD") in prices          # the actual asking price
    assert (5000.0, "USD") not in prices    # denomination, not a price
    assert (1000.0, "USD") not in prices
    assert len(listings) == 1
    # product text is cleaned up, not a mid-word fragment
    assert "cards with credit" in listings[0].product
    assert not listings[0].product.startswith(" ")


def test_embedding_scorer_prioritises_semantically():
    scorer = EmbeddingScorer(HashingEmbedder(dim=256), ["bitcoin market"])
    hit = DiscoveredLink(url="http://x.onion/a", anchor_text="bitcoin market listings")
    miss = DiscoveredLink(url="http://x.onion/b", anchor_text="cooking recipes and gardening")
    assert scorer.score(hit, 1) > scorer.score(miss, 1)


async def test_resolve_actors_clusters_shared_identifiers(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add_all([
            # ADDR1 appears on two pages and co-occurs with a handle on p1 -> one actor
            Ioc(page_url="http://p1.onion/", ioc_type="btc", value="ADDR1"),
            Ioc(page_url="http://p2.onion/", ioc_type="btc", value="ADDR1"),
            Ioc(page_url="http://p1.onion/", ioc_type="handle", value="darkvendor"),
            # ADDR2 is a singleton (one identifier, one page) -> not an actor
            Ioc(page_url="http://p3.onion/", ioc_type="btc", value="ADDR2"),
            # a victim email must NOT create an actor (excluded from STRONG_TYPES)
            Ioc(page_url="http://p1.onion/", ioc_type="email", value="victim@corp.com"),
        ])
        await s.commit()

    summary = await resolve_actors(db)
    assert summary["actors"] == 1

    async with db.session() as s:
        actors = (await s.execute(sa.select(Actor))).scalars().all()
        assert len(actors) == 1
        assert actors[0].page_count == 2
        idents = set((await s.execute(sa.select(ActorIdentifier.value))).scalars())
        assert {"ADDR1", "darkvendor"} <= idents
        assert "ADDR2" not in idents
        assert "victim@corp.com" not in idents  # breach victim, not an actor
    await db.dispose()
