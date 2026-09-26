import sqlalchemy as sa
import re

from umbra.compliance.policy import CompliancePolicy
from umbra.crawl.parse import DiscoveredLink
from umbra.crawl.scorer import KeywordScorer, StructuralScorer


def _score(url: str, keywords=None) -> float:
    scorer = StructuralScorer(KeywordScorer(keywords))
    return scorer.score(DiscoveredLink(url=url, anchor_text=""), depth=1)


def test_structural_prior_demotes_dead_ends():
    """Real URLs from a crawled frontier — 109 of 418 queued links were these."""
    product = _score("http://x.onion/?cat=100")
    for dead in (
        "http://x.onion/src/login.php",
        "http://x.onion/register.php",
        "http://x.onion/nojs/captcha",
        "http://x.onion/about",
        "http://x.onion/careers",
        "http://x.onion/assets/style.css",
    ):
        assert _score(dead) < product, dead


def test_structural_prior_boosts_where_indicators_live():
    plain = _score("http://x.onion/index.php")
    for good in (
        "http://x.onion/?cat=300",
        "http://x.onion/vendor/darkseller",
        "http://x.onion/product/1234",
        "http://x.onion/user/profile",
    ):
        assert _score(good) > plain, good


def test_dead_end_wins_ties():
    """'/shop/login' is a login page, not a shop page."""
    assert _score("http://x.onion/shop/login") < _score("http://x.onion/shop/item")


def test_dead_ends_are_demoted_not_dropped():
    """They sink to the bottom of the frontier but stay reachable — a regex
    should never make a page permanently uncrawlable."""
    assert _score("http://x.onion/login.php") > 0


def test_structural_prior_composes_with_keyword_focus():
    """The prior multiplies the inner score rather than replacing it, so keyword
    focus still ranks within a structural tier."""
    on_topic = _score("http://x.onion/vendor/drugs", keywords=["drugs"])
    off_topic = _score("http://x.onion/vendor/books", keywords=["drugs"])
    assert on_topic > off_topic


async def test_rescore_frontier_reprioritises_already_queued_links(tmp_path):
    """A scorer change is invisible to links already in the frontier: Page.score
    is written once at discovery. Observed live — with the structural prior
    active, the crawler still fetched login.php, because that row predated it."""
    from umbra.config import Settings
    from umbra.db import Database
    from umbra.factory import build_scorer
    from umbra.models import STATUS_CRAWLED, STATUS_DISCOVERED, Page
    from umbra.reprocess import rescore_frontier

    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'rs.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add_all([
            Page(url="http://x.onion/login.php", hostname="x.onion", status=STATUS_DISCOVERED,
                 depth=1, score=1.0, blocked=False, stored_content=False),
            Page(url="http://x.onion/?cat=100", hostname="x.onion", status=STATUS_DISCOVERED,
                 depth=1, score=1.0, blocked=False, stored_content=False),
            # already fetched: its score must not be touched, it no longer orders anything
            Page(url="http://x.onion/done", hostname="x.onion", status=STATUS_CRAWLED,
                 depth=1, score=1.0, content_sha256="s", blocked=False, stored_content=True),
        ])
        await s.commit()

    settings = Settings()
    settings.embeddings_enabled = False
    _, scorer = build_scorer(settings)
    result = await rescore_frontier(db, scorer)
    assert result["queued"] == 2 and result["rescored"] == 2

    async with db.session() as s:
        scores = dict(
            (await s.execute(sa.select(Page.url, Page.score))).all()
        )
    assert scores["http://x.onion/?cat=100"] > scores["http://x.onion/login.php"]
    assert scores["http://x.onion/done"] == 1.0  # crawled page left alone
    await db.dispose()


def test_keyword_scorer_prioritises_matches():
    scorer = KeywordScorer(["market", "vendor"])
    hit = DiscoveredLink(url="http://x.onion/market", anchor_text="Vendor market")
    miss = DiscoveredLink(url="http://x.onion/about", anchor_text="About us")
    assert scorer.score(hit, depth=1) > scorer.score(miss, depth=1)


def test_uniform_when_no_keywords():
    scorer = KeywordScorer([])
    link = DiscoveredLink(url="http://x.onion/whatever")
    assert scorer.score(link, depth=0) == 1.0


def test_policy_blocks_and_withholds_content():
    policy = CompliancePolicy(blocklist=[("weapons", re.compile(r"buy a gun", re.I))])
    decision = policy.evaluate("http://x.onion/", "click here to buy a GUN today", "text/html")
    assert decision.blocked is True
    assert decision.store_content is False
    assert "weapons" in decision.categories


def test_policy_never_stores_media_bytes_by_default():
    policy = CompliancePolicy(store_media=False)
    decision = policy.evaluate("http://x.onion/pic.jpg", None, "image/jpeg")
    assert decision.store_content is False
    assert decision.blocked is False


def test_policy_drops_known_bad_hash():
    policy = CompliancePolicy(known_bad_hashes={"abc123"})
    hit = policy.evaluate("http://x.onion/", "text", "text/html", content_sha256="ABC123")
    assert hit.blocked is True and hit.store_content is False
    assert hit.reason == "known-bad-hash"
    miss = policy.evaluate("http://x.onion/", "text", "text/html", content_sha256="deadbeef")
    assert miss.blocked is False and miss.store_content is True
