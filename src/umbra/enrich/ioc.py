"""Indicator-of-compromise / entity extraction.

A first, high-value enricher: cryptocurrency addresses, PGP fingerprints, operator
contact channels, victim emails, onion v3 addresses, and CVE identifiers. These are
exactly the entities a threat-intel or fraud product indexes and pivots on.
Regex-based and cheap, so it runs on every page inline; heavier models can be added
as separate enrichers.

One distinction drives most of the value here: **an address that identifies the
operator is not the same kind of fact as an address that identifies a victim.**
A vendor's ProtonMail contact and a leaked ``ceo@acme.com`` are both "emails", but
the first is evidence of who is selling and the second is evidence of who was
breached. Entity resolution clusters actors on the former and must never cluster
on the latter — merging two unrelated breaches because they share a victim domain
would be actively misleading. See ``intel/entities.py``.
"""

from __future__ import annotations

import re

from ..crawl.parse import ParsedPage
from ..models import Ioc, Page
from .pgpfp import find_fingerprints

_PATTERNS: dict[str, re.Pattern[str]] = {
    # Bitcoin: legacy base58 (1/3…) and bech32 (bc1…).
    "btc": re.compile(
        r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
    ),
    # Ethereum-style 20-byte hex address.
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    # Monero standard address (95 chars, starts 4…).
    "xmr": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    # Onion v3 (56-char base32 label).
    "onion": re.compile(r"\b[a-z2-7]{56}\.onion\b", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
}

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Mail hosts chosen specifically because they resist subpoena, require no identity,
# or are reachable over Tor. Nobody's payroll runs on cock.li — an address here is
# a channel someone published so buyers could reach *them*, which makes it an actor
# identifier rather than victim data. Corporate and consumer domains stay in the
# weak ``email`` bucket. Operator policy: extend freely, it is only a heuristic.
_CONTACT_DOMAINS = frozenset(
    {
        "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
        "tutanota.com", "tutanota.de", "tutamail.com", "tuta.io",
        "riseup.net", "systemli.org", "autistici.org", "disroot.org",
        "cock.li", "airmail.cc", "firemail.cc", "waifu.club",
        "onionmail.org", "onionmail.info", "secmail.pro", "dnmx.org",
        "elude.in", "mail2tor.com", "danwin1210.de", "torbox3uiot6wchz.onion",
        "ctemplar.com", "mailfence.com", "safe-mail.net", "sonar.email",
        "thesecure.biz", "exploit.im", "jabber.ru", "xmpp.jp", "jabb.im",
        "creep.im", "chatme.im", "swissjabber.de", "404.city",
    }
)

# ``Jabber: vendor@exploit.im`` — the label makes it a contact channel regardless
# of which host it sits on, so it is worth catching explicitly.
_JABBER = re.compile(
    r"(?:jabber|xmpp)\b\s*(?:id|address)?\s*[:\-=]?\s*"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.I,
)

# Vendor names only where the page explicitly labels them, and deliberately
# narrow, because a wrong handle is worse than no handle: entity resolution unions
# on these, so one bogus value shared across pages fuses unrelated actors into a
# single phantom.
#
# Two loosenings were tried against the crawled corpus and both had to go.
# Bare ``@handle`` matched an image host and an operating system, no vendors. And
# accepting ``-`` as a label delimiter turned every directory entry of the form
# "Mobile Store - Best unlocked cell phones" into a vendor called "Best" — the
# hyphen introduces a description, not a value. Hence: colon only, and no
# ``shop|store|merchant``, which occur inside ordinary site names.
_HANDLE = re.compile(
    r"\b(?:vendor|seller)\s*(?:name)?\s*:\s*([A-Za-z0-9][A-Za-z0-9_.\-]{2,31})\b",
    re.I,
)
_HANDLE_ALT = re.compile(
    r"\bsold\s+by\s*:?\s*([A-Za-z0-9][A-Za-z0-9_.\-]{2,31})\b", re.I
)
_HANDLE_STOPWORDS = frozenset(
    {
        "products", "product", "login", "register", "registration", "name",
        "page", "home", "info", "the", "and", "profile", "feedback", "rating",
        "unknown", "anonymous", "none", "null", "search", "category",
    }
)


def _email_type(address: str) -> str:
    """Classify an email as an operator contact channel or as victim data."""
    domain = address.rsplit("@", 1)[-1].lower()
    if domain.endswith(".onion") or domain in _CONTACT_DOMAINS:
        return "contact_email"
    return "email"


class IocExtractor:
    name = "ioc"

    def __init__(self, max_per_type: int = 200) -> None:
        self.max_per_type = max_per_type

    async def enrich(self, page: Page, parsed: ParsedPage) -> list[Ioc]:
        text = parsed.text or ""
        found: list[Ioc] = []
        counts: dict[str, int] = {}
        seen: set[tuple[str, str]] = set()

        def add(ioc_type: str, value: str) -> None:
            key = (ioc_type, value)
            if key in seen or counts.get(ioc_type, 0) >= self.max_per_type:
                return
            seen.add(key)
            counts[ioc_type] = counts.get(ioc_type, 0) + 1
            pos = text.lower().find(value.lower())
            context = text[max(0, pos - 80):pos + len(value) + 80] if pos >= 0 else None
            found.append(Ioc(page_url=page.url, ioc_type=ioc_type, value=value[:512],
                             context=context))

        fingerprints = find_fingerprints(text)
        for fingerprint in fingerprints:
            add("pgp_fp", fingerprint)

        for ioc_type, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                if ioc_type == "btc" and value.startswith(("1", "3")):
                    from .validation import bitcoin_base58_valid
                    if not bitcoin_base58_valid(value):
                        continue
                # Keyservers print key IDs as ``0x`` + 40 hex — byte-identical in
                # shape to an Ethereum address. Recording one as a wallet is not a
                # cosmetic error: ``eth`` links actors, so a shared fingerprint
                # would show up as a shared wallet and misattribute the payment
                # trail. If it matches a key on this page, it is a key.
                if ioc_type == "eth" and value[2:].upper() in fingerprints:
                    continue
                add(ioc_type, value)

        # A key we can see but can't parse is still worth flagging — just not as an
        # identifier, since "present" cannot link anything to anything.
        if "BEGIN PGP PUBLIC KEY BLOCK" in text and "pgp_fp" not in counts:
            add("pgp", "present")

        labelled: set[str] = set()
        for match in _JABBER.finditer(text):
            address = match.group(1)
            labelled.add(address)
            add("jabber", address)

        for match in _EMAIL.finditer(text):
            address = match.group(0)
            if address in labelled:
                continue  # already recorded as a jabber contact
            add(_email_type(address), address)

        for pattern in (_HANDLE, _HANDLE_ALT):
            for match in pattern.finditer(text):
                handle = match.group(1)
                if handle.lower() in _HANDLE_STOPWORDS:
                    continue
                add("handle", handle)

        return found
