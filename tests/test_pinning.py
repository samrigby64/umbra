"""Pinned seeds keep the crawl where the intelligence is.

Measured on a pack-seeded corpus: links leaving a seeded host were 93-96% empty
at every depth, while pages deeper inside the same host were the best signal in
the table — and 72% of the next pass's queue was off-host. These tests pin down
the mechanism: off-host links from pinned hosts are demoted (never dropped),
pinned hosts get a larger budget, unpinned seeds are unaffected, and rescoring
an existing frontier applies the same rule.
"""

import sqlalchemy as sa

from umbra.config import Settings
from umbra.crawl.parse import DiscoveredLink
from umbra.crawl.scheduler import CrawlItem, Scheduler
from umbra.crawl.scorer import KeywordScorer, StructuralScorer, prioritise
from umbra.db import Database
from umbra.models import STATUS_CRAWLED, STATUS_DISCOVERED, Page
from umbra.reprocess import rescore_frontier


def _link(url: str) -> DiscoveredLink:
    return DiscoveredLink(url=url, anchor_text="")


def test_prioritise_demotes_off_host_links_only_in_targeted_lineages():
    scorer = KeywordScorer([])
    kw = dict(pinned_hosts={"target.onion"}, off_host_factor=0.1)

    on_host = prioritise(scorer, _link("http://target.onion/vendor/x"), 1, targeted=True, **kw)
    off_host = prioritise(scorer, _link("http://elsewhere.onion/"), 1, targeted=True, **kw)
    # same off-host link found in a directory crawl: the outbound links ARE the point
    from_wiki = prioritise(scorer, _link("http://elsewhere.onion/"), 1, targeted=False, **kw)
    # a link to a *different* pinned host is fine — it is also a target
    to_other_pin = prioritise(
        scorer, _link("http://second.onion/"), 1, targeted=True,
        pinned_hosts={"target.onion", "second.onion"}, off_host_factor=0.1,
    )

    assert on_host == 1.0 and from_wiki == 1.0 and to_other_pin == 1.0
    assert off_host == 0.1
    assert off_host > 0  # demoted, never dropped


def test_off_host_demotion_composes_with_the_structural_prior():
    """A category page on another site still ranks above a login page on the
    pinned one — priorities multiply rather than replace each other."""
    scorer = StructuralScorer(KeywordScorer([]))
    kw = dict(targeted=True, pinned_hosts={"target.onion"}, off_host_factor=0.1)
    off_host_category = prioritise(scorer, _link("http://other.onion/?cat=1"), 1, **kw)
    on_host_login = prioritise(scorer, _link("http://target.onion/login.php"), 1, **kw)
    on_host_category = prioritise(scorer, _link("http://target.onion/?cat=1"), 1, **kw)
    assert on_host_category > off_host_category > on_host_login


async def _scheduler(tmp_path, **overrides):
    settings = Settings()
    settings.database_url = f"sqlite+aiosqlite:///{tmp_path / 'pin.db'}"
    for k, v in overrides.items():
        setattr(settings, k, v)
    db = Database(settings.database_url)
    await db.create_all()
    scheduler = Scheduler(db, settings)
    await scheduler.load()
    return scheduler, db, settings


async def test_pin_is_persisted_and_rehydrated_on_resume(tmp_path):
    scheduler, db, settings = await _scheduler(tmp_path)
    await scheduler.seed(["http://target.onion/"], pin=True)
    await scheduler.seed(["http://wiki.onion/"])  # a directory: not pinned
    assert scheduler.pinned_hosts == {"target.onion"}

    async with db.session() as s:
        pinned = dict((await s.execute(sa.select(Page.url, Page.pinned))).all())
    assert pinned["http://target.onion/"] is True
    assert not pinned["http://wiki.onion/"]

    # a fresh scheduler (restart) knows the pins without being told again
    fresh = Scheduler(db, settings)
    await fresh.load()
    assert fresh.pinned_hosts == {"target.onion"}

    # re-seeding an already-known URL with pin=True pins it too
    await fresh.seed(["http://wiki.onion/"], force=True, pin=True)
    assert "wiki.onion" in fresh.pinned_hosts
    await db.dispose()


async def test_pinned_hosts_get_the_larger_budget(tmp_path):
    scheduler, db, _ = await _scheduler(
        tmp_path, max_pages_per_domain=2, max_pages_per_domain_pinned=5
    )
    await scheduler.seed(["http://target.onion/"], pin=True)
    await scheduler.seed(["http://other.onion/"])

    def item(url):
        return CrawlItem(url=url, depth=1, parent=None, score=1.0)

    added_target = sum([await scheduler.add(item(f"http://target.onion/{i}")) for i in range(10)])
    added_other = sum([await scheduler.add(item(f"http://other.onion/{i}")) for i in range(10)])
    assert added_target == 4   # 5 minus the seed itself
    assert added_other == 1    # 2 minus the seed itself
    await db.dispose()


async def test_targeted_travels_with_the_item_through_claim(tmp_path):
    """The crawler learns a page's mode from the claimed item, so the flag has to
    survive the round trip through the database."""
    scheduler, db, _ = await _scheduler(tmp_path)
    await scheduler.seed(["http://target.onion/"], pin=True)
    await scheduler.seed(["http://wiki.onion/"])
    await scheduler.add(CrawlItem(url="http://target.onion/x", depth=1,
                                  parent="http://target.onion/", score=0.5, targeted=True))
    await scheduler.add(CrawlItem(url="http://wiki.onion/x", depth=1,
                                  parent="http://wiki.onion/", score=0.5, targeted=False))
    claimed = {}
    while (item := await scheduler.claim()) is not None:
        claimed[item.url] = item.targeted
    assert claimed["http://target.onion/"] is True
    assert claimed["http://target.onion/x"] is True
    assert claimed["http://wiki.onion/"] is False
    assert claimed["http://wiki.onion/x"] is False
    await db.dispose()


def _page(url, host, parent=None, pinned=False, targeted=False, status=STATUS_DISCOVERED):
    return Page(url=url, hostname=host, parent_url=parent, depth=0 if parent is None else 1,
                score=1.0, pinned=pinned, targeted=targeted, status=status, blocked=False,
                stored_content=False, content_sha256="s" if status == STATUS_CRAWLED else None)


async def test_pinning_a_seed_propagates_to_its_existing_descendants(tmp_path):
    """A pack applied to a frontier built before it was pinned: the whole lineage
    below the seed flips to targeted, however deep — and a neighbouring wiki
    lineage does not."""
    scheduler, db, _ = await _scheduler(tmp_path)
    async with db.session() as s:
        s.add_all([
            _page("http://target.onion/", "target.onion", status=STATUS_CRAWLED),
            _page("http://target.onion/a", "target.onion", parent="http://target.onion/",
                  status=STATUS_CRAWLED),
            _page("http://hop.onion/", "hop.onion", parent="http://target.onion/a",
                  status=STATUS_CRAWLED),                                           # one hop off
            _page("http://far.onion/", "far.onion", parent="http://hop.onion/"),   # two hops off
            _page("http://wiki.onion/", "wiki.onion", status=STATUS_CRAWLED),
            _page("http://linked.onion/", "linked.onion", parent="http://wiki.onion/"),
        ])
        await s.commit()
    await scheduler.load()

    await scheduler.seed(["http://target.onion/"], pin=True)

    async with db.session() as s:
        targeted = dict((await s.execute(sa.select(Page.url, Page.targeted))).all())
    assert all(targeted[u] for u in (
        "http://target.onion/", "http://target.onion/a", "http://hop.onion/", "http://far.onion/"
    ))
    assert not targeted["http://wiki.onion/"] and not targeted["http://linked.onion/"]
    await db.dispose()


async def test_rescore_demotes_off_host_links_at_any_depth_in_a_targeted_lineage(tmp_path):
    """The live finding that forced the lineage design: with only immediate
    children demoted, a page one hop off a target handed out full-priority links
    to a second hop, and 71% of the next pass was still off-target."""
    settings = Settings()
    settings.embeddings_enabled = False
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'rs.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add_all([
            _page("http://target.onion/", "target.onion", pinned=True, targeted=True,
                  status=STATUS_CRAWLED),
            # a neutral path: the structural prior must not be what separates these
            _page("http://target.onion/page", "target.onion", parent="http://target.onion/",
                  targeted=True),
            _page("http://hop.onion/", "hop.onion", parent="http://target.onion/",
                  targeted=True, status=STATUS_CRAWLED),
            _page("http://far.onion/", "far.onion", parent="http://hop.onion/", targeted=True),
            _page("http://wiki.onion/", "wiki.onion", status=STATUS_CRAWLED),
            _page("http://linked.onion/", "linked.onion", parent="http://wiki.onion/"),
        ])
        await s.commit()

    from umbra.factory import build_scorer
    _, scorer = build_scorer(settings)
    await rescore_frontier(db, scorer, off_host_factor=0.1)

    async with db.session() as s:
        scores = dict((await s.execute(sa.select(Page.url, Page.score))).all())
    assert scores["http://far.onion/"] == 0.1            # two hops off a target: demoted
    assert scores["http://target.onion/page"] == 1.0     # deeper into the target: not
    assert scores["http://linked.onion/"] == 1.0         # directory lineage: not
    await db.dispose()
