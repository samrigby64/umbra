"""Structured extractors: leaked credentials and marketplace listings.

These are the concrete, high-value record types buyers query — beyond the
generic IOCs of :mod:`umbra.enrich.ioc`. Both follow the ``Enricher`` protocol
(return a list of ORM records the scheduler persists), and both are cheap,
regex-based, and run inline on every page.

Compliance note: the credential extractor stores only a **SHA-256** of each
password, never the plaintext. The corpus becomes a breach-*lookup* index (match
by email/domain, optionally verify a hash) rather than a password store.
"""

from __future__ import annotations

import hashlib
import re

from ..crawl.parse import ParsedPage
from ..models import Credential, Listing, Page

# email:password pairs, as they appear in combolists/dumps.
_CRED_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*[:|]\s*(\S{3,80})")

# Price tokens in common currencies.
_PRICE_RES = [
    (re.compile(r"\$\s?(\d{1,7}(?:\.\d{1,2})?)"), "USD"),
    (re.compile(r"€\s?(\d{1,7}(?:\.\d{1,2})?)"), "EUR"),
    (re.compile(r"£\s?(\d{1,7}(?:\.\d{1,2})?)"), "GBP"),
    (re.compile(r"\b(\d{1,7}(?:\.\d{1,2})?)\s?(USD|EUR|GBP)\b"), None),
    (re.compile(r"\b(\d(?:\.\d{1,8})?)\s?(BTC|XMR|ETH)\b", re.I), None),
]

# A number sitting inside a range phrase is a *denomination*, not an asking price.
# Real example from a carding market: "10 x cards with credit from 1000 to 5000 USD
# … $90" — the 1000/5000 describe the goods; only $90 is the price. Without this,
# every listing produced a phantom row at the range bound.
_RANGE_BEFORE = re.compile(r"(?:\b(?:from|to|between|upto|up\s+to)\s*|[-–—~]\s*)$", re.I)


class CredentialExtractor:
    name = "credentials"

    def __init__(self, max_per_page: int = 500) -> None:
        self.max_per_page = max_per_page

    async def enrich(self, page: Page, parsed: ParsedPage) -> list[Credential]:
        text = parsed.text or ""
        out: list[Credential] = []
        seen: set[tuple[str, str]] = set()
        for match in _CRED_RE.finditer(text):
            email = match.group(1).lower()
            password = match.group(2)
            key = (email, password)
            if key in seen:
                continue
            seen.add(key)
            domain = email.rsplit("@", 1)[-1] if "@" in email else None
            out.append(
                Credential(
                    page_url=page.url,
                    email=email[:320],
                    domain=domain[:255] if domain else None,
                    password_sha256=hashlib.sha256(password.encode("utf-8")).hexdigest(),
                )
            )
            if len(out) >= self.max_per_page:
                break
        return out


class ListingExtractor:
    name = "listings"

    def __init__(self, max_per_page: int = 200, context_chars: int = 70) -> None:
        self.max_per_page = max_per_page
        self.context_chars = context_chars

    async def enrich(self, page: Page, parsed: ParsedPage) -> list[Listing]:
        if parsed.listing_blocks:
            results, seen = [], set()
            for block in parsed.listing_blocks:
                for record in await self.enrich(page, ParsedPage(url=parsed.url, text=block)):
                    key = (record.product, record.price, record.currency)
                    if key not in seen:
                        results.append(record)
                        seen.add(key)
                    if len(results) >= self.max_per_page:
                        return results
            return results
        text = parsed.text or ""
        out: list[Listing] = []
        seen: set[tuple[float, str, str]] = set()
        for pattern, fixed_currency in _PRICE_RES:
            for m in pattern.finditer(text):
                try:
                    price = float(m.group(1))
                except ValueError:
                    continue
                currency = fixed_currency or m.group(2).upper()
                if _RANGE_BEFORE.search(text[max(0, m.start() - 24) : m.start()]):
                    continue  # a range bound (e.g. "from 1000 to 5000 USD"), not a price

                # Use the text just before the price as the product context.
                start = max(0, m.start() - self.context_chars)
                context = text[start : m.start()]
                # The window usually starts mid-word ("…ce Quantity"); drop the
                # partial token and collapse whitespace so the product reads cleanly.
                if start > 0 and not text[start - 1].isspace() and " " in context:
                    context = context.split(" ", 1)[1]
                product = " ".join(context.split()) or None
                key = (round(price, 8), currency, product or "")
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Listing(
                        page_url=page.url,
                        product=product[:512] if product else None,
                        price=price,
                        currency=currency,
                        context=text[max(0, m.start()-self.context_chars):m.end()+70],
                    )
                )
                if len(out) >= self.max_per_page:
                    return out
        return out
