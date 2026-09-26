import zlib

import numpy as np

from umbra.crawl.parse import ParsedPage
from umbra.enrich.llm import FakeLlmClient, LlmEnricher
from umbra.intel.embeddings import HashingEmbedder
from umbra.models import Page


async def test_llm_enricher_sets_page_fields():
    enricher = LlmEnricher(FakeLlmClient(), min_chars=10)
    page = Page(url="http://x.onion/")
    parsed = ParsedPage(url="http://x.onion/", text="A vendor market selling various goods " * 5)

    iocs = await enricher.enrich(page, parsed)

    assert page.page_type == "marketplace"
    assert page.summary  # non-empty
    assert page.language == "en"
    assert isinstance(iocs, list)


async def test_llm_enricher_skips_short_text():
    enricher = LlmEnricher(FakeLlmClient(), min_chars=200)
    page = Page(url="http://x.onion/")
    parsed = ParsedPage(url="http://x.onion/", text="too short")

    iocs = await enricher.enrich(page, parsed)
    assert iocs == []
    assert page.page_type is None


def test_hashing_embedder_uses_stable_hash():
    # Pins deterministic, cross-process hashing. Fails if reverted to the
    # randomised built-in hash() — a single token must land in the crc32 bucket.
    emb = HashingEmbedder(dim=64)
    v = emb.embed("bitcoin")
    expected_bucket = zlib.crc32(b"bitcoin") % 64
    assert np.count_nonzero(v) == 1
    assert v[expected_bucket] == 1.0


def test_hashing_embedder_is_normalised_and_lexically_meaningful():
    emb = HashingEmbedder(dim=128)
    v = emb.embed("bitcoin marketplace vendor")
    assert abs(np.linalg.norm(v) - 1.0) < 1e-5

    query = emb.embed("bitcoin vendor")
    related = emb.embed("a bitcoin vendor marketplace listing")
    unrelated = emb.embed("gardening tips for tomatoes")
    assert float(query @ related) > float(query @ unrelated)
