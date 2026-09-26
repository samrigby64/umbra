"""Shared construction of the crawl pipeline, used by both the CLI and the API.

Keeps the "how do I assemble a Crawler from Settings" logic in one place so the
`umbra crawl`/`worker` commands and the GUI's Start-crawl button behave identically.
"""

from __future__ import annotations

from .compliance.policy import CompliancePolicy
from .config import Settings
from .crawl.crawler import Crawler
from .crawl.scorer import EmbeddingScorer, KeywordScorer, StructuralScorer
from .db import Database
from .enrich.ioc import IocExtractor
from .enrich.llm import AnthropicLlmClient, LlmEnricher
from .enrich.structured import CredentialExtractor, ListingExtractor
from .intel.embeddings import build_embedder
from .logging import get_logger

log = get_logger("factory")


def build_enrichers(settings: Settings) -> list:
    enrichers: list = [IocExtractor(), CredentialExtractor(), ListingExtractor()]
    if settings.llm_enabled:
        try:
            enrichers.append(
                LlmEnricher(
                    AnthropicLlmClient(
                        settings.llm_model, settings.llm_max_chars, settings.llm_timeout_s
                    )
                )
            )
            log.info("LLM enrichment enabled (%s)", settings.llm_model)
        except Exception as exc:  # missing SDK or credentials
            log.warning("LLM enrichment unavailable (%s); continuing without it", exc)
    return enrichers


def build_scorer(settings: Settings, embedder=None):
    """Return (embedder, scorer) for ``settings``.

    Shared by the crawler and by frontier rescoring so the two can never disagree
    about how a link is prioritised — a rescore that used a different scorer than
    the crawl would silently reorder the queue on the wrong basis.
    """
    if embedder is None and settings.embeddings_enabled:
        embedder = build_embedder(settings)
    if settings.focus_keywords and embedder is not None:
        scorer = EmbeddingScorer(embedder, settings.focus_keywords)  # semantic focused crawl
    else:
        scorer = KeywordScorer(settings.focus_keywords)
    if settings.structural_priority:
        # Applies with or without focus keywords: login/registration pages are
        # dead ends on every crawl, vendor and category pages are where the
        # indicators are.
        scorer = StructuralScorer(scorer)
    return embedder, scorer


def build_crawler(settings: Settings, db: Database):
    """Return (crawler, fetcher). The caller owns closing the fetcher."""
    from .fetch.client import TorFetcher

    fetcher = TorFetcher(
        settings.tor_socks_host,
        settings.tor_socks_port,
        user_agent=settings.user_agent,
        timeout=settings.request_timeout,
        retries=settings.fetch_retries,
        max_bytes=settings.max_response_bytes,
        use_tor=settings.use_tor,
        allowed_hosts=settings.allowed_hosts,
    )
    embedder, scorer = build_scorer(settings)
    policy = CompliancePolicy.from_file(
        settings.blocklist_path,
        known_bad_hashes_path=settings.known_bad_hashes_path,
        store_text=settings.store_text,
        store_html=settings.store_html,
        store_media=settings.store_media,
    )
    crawler = Crawler(
        settings, db, fetcher, scorer, policy,
        enrichers=build_enrichers(settings), embedder=embedder,
    )
    return crawler, fetcher
