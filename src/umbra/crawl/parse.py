"""HTML parsing and link extraction.

Uses selectolax (lexbor) rather than BeautifulSoup — it is dramatically faster,
which matters at crawl scale. All URL handling goes through :func:`normalize_url`
so relative links, fragments, and casing are handled in exactly one place
(the original project reimplemented ad-hoc URL joining in several files).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

from selectolax.parser import HTMLParser

# Absolute onion URLs mentioned in page *text* (not just <a href>).
_ONION_URL_RE = re.compile(r"https?://[a-z0-9.\-]*\.onion(?:/[^\s\"'<>]*)?", re.I)

_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "#")


@dataclass
class DiscoveredLink:
    url: str
    anchor_text: str = ""


@dataclass
class ParsedPage:
    url: str
    title: str | None = None
    description: str | None = None
    keywords: str | None = None
    text: str = ""
    links: list[DiscoveredLink] = field(default_factory=list)
    listing_blocks: list[str] = field(default_factory=list)


def normalize_url(base: str, href: str | None) -> str | None:
    """Resolve ``href`` against ``base`` and canonicalise it.

    Returns ``None`` for non-http(s) links or anything unusable.
    """
    if not href:
        return None
    href = href.strip()
    if not href or href.lower().startswith(_SKIP_SCHEMES):
        return None
    try:
        absolute = urljoin(base, href)
        absolute, _ = urldefrag(absolute)
        parsed = urlparse(absolute)
    except ValueError:
        # Python 3.12 validates bracketed hosts and raises on e.g. "http://[dot]/".
        # An href is attacker-written text; one malformed link must skip *that
        # link*, not abort the whole page. Seen live: a single bad anchor on a
        # marketplace category page threw the page away on every attempt.
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    # Lower-case the host only (paths on the dark web are case-sensitive).
    host = parsed.netloc.lower()
    if host != parsed.netloc:
        absolute = absolute.replace(parsed.netloc, host, 1)
    return absolute


def is_onion(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host.endswith(".onion")


def hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def parse_page(html: str, base_url: str) -> ParsedPage:
    tree = HTMLParser(html or "")

    # Drop non-content nodes so inline JS/CSS doesn't pollute the extracted text,
    # embeddings, or IOC extraction (e.g. hex in minified JS reading as an address).
    for node in tree.css("script, style, noscript, template"):
        node.decompose()

    title_node = tree.css_first("title")
    title = title_node.text(strip=True) if title_node else None

    description = keywords = None
    for meta in tree.css("meta"):
        name = (meta.attributes.get("name") or "").lower()
        if name == "description":
            description = meta.attributes.get("content")
        elif name == "keywords":
            keywords = meta.attributes.get("content")

    body = tree.body if tree.body is not None else tree.root
    text = body.text(separator=" ", strip=True) if body is not None else ""
    # Keep product rows apart before flattening text. Prefer leaf cards to avoid
    # extracting an entire catalogue as one product.
    selector = 'tr, [itemtype*="schema.org/Product"], .product, .listing'
    blocks = []
    for node in tree.css(selector):
        if any(child != node for child in node.css(selector)):
            continue
        value = node.text(separator=" ", strip=True)
        if value and len(value) <= 4000:
            blocks.append(value)
        if len(blocks) >= 500:
            break

    links: list[DiscoveredLink] = []
    seen: set[str] = set()
    for anchor in tree.css("a[href]"):
        url = normalize_url(base_url, anchor.attributes.get("href"))
        if not url or url in seen:
            continue
        seen.add(url)
        links.append(DiscoveredLink(url=url, anchor_text=anchor.text(strip=True)[:200]))

    # Onion URLs referenced in plain text (common on index/paste pages).
    for match in _ONION_URL_RE.finditer(text):
        url = normalize_url(base_url, match.group(0))
        if url and url not in seen:
            seen.add(url)
            links.append(DiscoveredLink(url=url))

    return ParsedPage(
        url=base_url,
        title=title,
        description=description,
        keywords=keywords,
        text=text,
        links=links,
        listing_blocks=blocks,
    )
