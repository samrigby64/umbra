"""Link relevance scoring — the seam for *focused / intelligent crawling* (#2).

The crawler pulls from a priority frontier ordered by score, so replacing this
one class is all it takes to go from "random sampling" to "crawl the most
promising links first". Today's implementation is a transparent keyword scorer;
tomorrow's can be a trained classifier or an embedding-similarity model that
implements the same ``score()`` signature.
"""

from __future__ import annotations

import re
from typing import Protocol

import numpy as np

from .parse import DiscoveredLink, hostname


class Scorer(Protocol):
    def score(self, link: DiscoveredLink, depth: int) -> float:
        """Return a priority for ``link``. Higher = crawl sooner."""
        ...


class KeywordScorer:
    """Base priority of 1.0 plus one point per focus keyword found in the anchor
    text or URL. With no keywords configured, every link scores 1.0 (uniform),
    which degrades gracefully to a breadth-first crawl.
    """

    def __init__(self, keywords: list[str] | None = None) -> None:
        self.keywords = [k.lower() for k in (keywords or []) if k.strip()]

    def score(self, link: DiscoveredLink, depth: int) -> float:
        if not self.keywords:
            return 1.0
        haystack = f"{link.anchor_text} {link.url}".lower()
        hits = sum(1 for kw in self.keywords if kw in haystack)
        return 1.0 + hits


class EmbeddingScorer:
    """Semantic focused crawling: score a link by cosine similarity between its
    anchor-text/URL embedding and the centroid of the focus topics.

    Unlike keyword matching, this ranks a link about "narcotics" highly for a
    focus of "drugs" even with no shared substring. Swap the embedder for a real
    model and this becomes genuinely intelligent link prioritisation.
    """

    def __init__(self, embedder, keywords: list[str] | None = None) -> None:
        self.embedder = embedder
        self.keywords = [k for k in (keywords or []) if k.strip()]
        self.centroid = None
        if self.keywords:
            centroid = np.mean([embedder.embed(k) for k in self.keywords], axis=0)
            norm = np.linalg.norm(centroid)
            self.centroid = centroid / norm if norm > 0 else centroid

    def score(self, link: DiscoveredLink, depth: int) -> float:
        if self.centroid is None:
            return 1.0
        vec = self.embedder.embed(f"{link.anchor_text} {link.url}")
        similarity = float(vec @ self.centroid)  # both unit-normalised => cosine
        return 1.0 + max(0.0, similarity)


# Pages that exist on nearly every site and never carry intelligence. Measured on
# a real 418-link frontier, "login.php" and "register.php" alone were 69 of them —
# a sixth of the queue, all guaranteed dead ends, competing on equal footing with
# product pages because an unfocused crawl scores every link 1.0.
_DEAD_END = re.compile(
    r"(?:^|[/_?&=-])(?:log[_-]?in|log[_-]?out|sign[_-]?in|sign[_-]?up|register|registration"
    r"|account|password|passwd|forgot|reset|captcha|cart|basket|checkout|terms|tos|privacy"
    r"|legal|imprint|about|careers?|jobs?|contact|faq|help|support|donate|rss|feed|sitemap"
    r"|.*\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip|gz|exe))(?:$|[/._?&=-])",
    re.I,
)

# Where listings, vendors and their keys actually live.
_HIGH_VALUE = re.compile(
    r"(?:^|[/_?&=-])(?:vendor|seller|shop|store|market|product|listing|listings|item|items"
    r"|offer|offers|cat|category|categories|catalog|profile|user|users|review|reviews"
    r"|feedback|pgp|escrow)(?:$|[/._?&=-])",
    re.I,
)


class StructuralScorer:
    """Wraps another scorer with a prior based on what a URL *is*.

    Focus keywords are per-crawl and often absent; this prior is not. A sign-up
    form is worthless on every crawl regardless of topic, and a vendor or category
    page is where indicators concentrate. Without it an unfocused crawl treats
    both identically, which is measurably what happened: 70 of 79 reachable hosts
    yielded exactly one page and 37% of fetches produced no records at all.

    Deliberately multiplicative and non-zero — dead ends sink to the bottom of the
    frontier rather than being dropped, so they are still reachable once the
    worthwhile links are exhausted, and no legitimate page is silently unreachable
    because of a regex.
    """

    DEAD_END_FACTOR = 0.05
    HIGH_VALUE_FACTOR = 2.0

    def __init__(self, inner: Scorer) -> None:
        self.inner = inner

    def prior(self, url: str) -> float:
        # Dead-end wins ties: "/shop/login" is still a login page.
        if _DEAD_END.search(url):
            return self.DEAD_END_FACTOR
        if _HIGH_VALUE.search(url):
            return self.HIGH_VALUE_FACTOR
        return 1.0

    def score(self, link: DiscoveredLink, depth: int) -> float:
        return self.inner.score(link, depth) * self.prior(link.url)


def prioritise(
    scorer: Scorer,
    link: DiscoveredLink,
    depth: int,
    *,
    targeted: bool,
    pinned_hosts: set[str],
    off_host_factor: float,
) -> float:
    """The priority a discovered link is stored with.

    Scorers only see the link; this adds the one thing they cannot know — what
    kind of crawl found it. In a *targeted* lineage (one descending from a pinned
    seed) any link to a host that is not itself pinned is demoted, however many
    hops out it was found. On a live corpus 93-96% of such pages carried
    nothing, at every depth, while pages deeper inside the pinned hosts were the
    best signal in the table. An untargeted lineage — a directory or wiki seed,
    where the outbound links are the point — is never demoted.

    Used by the crawler at discovery and by frontier rescoring, so the two can
    never rank the same link differently.
    """
    score = scorer.score(link, depth)
    if targeted and hostname(link.url) not in pinned_hosts:
        score *= off_host_factor
    return score
