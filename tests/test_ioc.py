"""Tests for actor-identifier extraction: PGP fingerprints, contacts, handles.

These feed entity resolution, where a false positive is worse than a miss — it
merges two unrelated actors into one. Several cases below are real strings taken
from crawled pages that broke an earlier version of the extractor.
"""

import base64
import hashlib
import struct

import sqlalchemy as sa

from umbra.crawl.parse import ParsedPage
from umbra.db import Database
from umbra.enrich.ioc import IocExtractor
from umbra.enrich.pgpfp import find_fingerprints
from umbra.intel.entities import resolve_actors
from umbra.models import Actor, Ioc, Page


async def _extract(text: str) -> dict[str, set[str]]:
    parsed = ParsedPage(url="http://x.onion/", text=text)
    iocs = await IocExtractor().enrich(Page(url="http://x.onion/"), parsed)
    out: dict[str, set[str]] = {}
    for ioc in iocs:
        out.setdefault(ioc.ioc_type, set()).add(ioc.value)
    return out


async def test_ioc_extraction():
    text = (
        "Donate BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 or ETH "
        "0x52908400098527886E0F7030069857D2E4169EE7. "
        "Contact admin@darkmail.onion. Affected by CVE-2021-44228. "
        "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    )
    found = await _extract(text)

    assert found["btc"] == {"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"}
    assert found["eth"] == {"0x52908400098527886E0F7030069857D2E4169EE7"}
    assert found["cve"] == {"CVE-2021-44228"}
    assert found["pgp"] == {"present"}
    # a mailbox hosted on a hidden service is an anonymous contact channel by
    # construction — nobody runs corporate mail there — so it identifies an
    # operator, not a breach victim.
    assert found["contact_email"] == {"admin@darkmail.onion"}
    assert "email" not in found


def _armored_key(old_format: bool = False) -> tuple[str, str]:
    """Build a minimal armoured v4 public key; return (armour, expected fingerprint)."""
    body = b"\x04" + struct.pack(">I", 1500000000) + b"\x01" + b"\xAA" * 64
    if old_format:
        header = bytes([0x80 | (6 << 2) | 1]) + struct.pack(">H", len(body))
    else:
        header = bytes([0xC0 | 6, len(body)])  # new format, one-byte length (<192)
    packet = header + body
    armour = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "Version: GnuPG v2\n\n"
        + base64.b64encode(packet).decode()
        + "\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----"
    )
    expected = (
        hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).hexdigest().upper()
    )
    return armour, expected


def test_fingerprint_computed_from_armoured_block():
    armour, expected = _armored_key()
    assert find_fingerprints(f"contact me {armour} thanks") == [expected]


def test_fingerprint_handles_old_format_packet_header():
    armour, expected = _armored_key(old_format=True)
    assert find_fingerprints(armour) == [expected]


def test_fingerprint_from_gpg_display_format():
    """The `gpg --fingerprint` display format — two spaced halves."""
    text = "Key fingerprint = 0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567"
    assert find_fingerprints(text) == ["0123456789ABCDEF0123456789ABCDEF01234567"]


def test_bare_hex_needs_pgp_context():
    digest = "A" * 40
    assert find_fingerprints(f"PGP fingerprint: {digest}") == [digest]
    # the same run with no PGP context is far more likely a SHA-1 digest
    assert find_fingerprints(f"sha1sum of the archive is {digest}") == []


def test_large_decimal_is_not_a_fingerprint():
    """1208925819614629174706176 (2**80) appeared on a crawled page and was
    matched by a looser pattern — digits alone must never look like a key."""
    assert find_fingerprints("PGP key 1208925819614629174706176 posted") == []


def test_malformed_armour_does_not_raise():
    assert (
        find_fingerprints(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!not base64!!!\n"
            "-----END PGP PUBLIC KEY BLOCK-----"
        )
        == []
    )


async def test_operator_contacts_separated_from_victim_emails():
    """Both are 'emails'; only one identifies the person selling."""
    found = await _extract(
        "Vendor contact test.vendor@protonmail.com or test.contact@riseup.net. "
        "Fresh dump includes ceo@acme.com and hr@acme.com."
    )
    assert found["contact_email"] == {"test.vendor@protonmail.com", "test.contact@riseup.net"}
    assert found["email"] == {"ceo@acme.com", "hr@acme.com"}


async def test_jabber_label_wins_over_plain_email():
    found = await _extract("Jabber: darkvendor@thesecure.biz for orders")
    assert found["jabber"] == {"darkvendor@thesecure.biz"}
    assert "email" not in found  # not double-counted as victim data


async def test_labelled_vendor_handles():
    found = await _extract("Vendor: ExampleVendorUK  ...  Sold by: SampleShop")
    assert found["handle"] == {"ExampleVendorUK", "SampleShop"}


async def test_handle_stopwords_reject_page_furniture():
    """'Vendor: Products Login' is a nav bar, not a vendor called 'Products'."""
    found = await _extract("Vendor: Products Login Register")
    assert "handle" not in found


async def test_key_id_in_0x_notation_is_not_an_ethereum_wallet():
    """A crawled keyserver page printed its fingerprint as 0x + 40 hex, which the
    Ethereum pattern happily matched — the corpus's only 'wallet' was a PGP key."""
    fingerprint = "FEEDFACECAFEBEEF0123456789ABCDEF01234567"
    found = await _extract(f"PGP fingerprint 0x{fingerprint} — search the keyserver")
    assert found["pgp_fp"] == {fingerprint}
    assert "eth" not in found


async def test_genuine_ethereum_address_still_extracted():
    found = await _extract("Send ETH to 0x52908400098527886E0F7030069857D2E4169EE7 now")
    assert found["eth"] == {"0x52908400098527886E0F7030069857D2E4169EE7"}


async def test_unparseable_key_still_flagged_but_not_as_identifier():
    found = await _extract(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n@@@@\n-----END PGP PUBLIC KEY BLOCK-----"
    )
    assert found["pgp"] == {"present"}
    assert "pgp_fp" not in found


async def test_actors_cluster_on_shared_pgp_fingerprint(tmp_path):
    """The payoff: one vendor, two markets, different wallets — same key."""
    fingerprint = "FEEDFACECAFEBEEF0123456789ABCDEF01234567"
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'fp.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add_all([
            Ioc(page_url="http://market-a.onion/", ioc_type="pgp_fp", value=fingerprint),
            Ioc(page_url="http://market-a.onion/", ioc_type="btc", value="ADDR_OLD"),
            Ioc(page_url="http://market-b.onion/", ioc_type="pgp_fp", value=fingerprint),
            Ioc(page_url="http://market-b.onion/", ioc_type="btc", value="ADDR_NEW"),
            # a victim address on the same page must not join the cluster
            Ioc(page_url="http://market-b.onion/", ioc_type="email", value="victim@acme.com"),
        ])
        await s.commit()

    assert (await resolve_actors(db))["actors"] == 1
    async with db.session() as s:
        actor = (await s.execute(sa.select(Actor))).scalars().one()
        assert actor.page_count == 2  # the rotation is now visible as one actor
    await db.dispose()
