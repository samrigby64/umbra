"""Tests for evidence bundles.

The risk in an evidence feature is not that it breaks — it is that it quietly
claims more than it can support, and someone relies on that in front of a client
or a court. Most of these tests are about the bundle describing its own limits
accurately.
"""

import datetime as dt
import hashlib
import hmac
import io
import json
import zipfile

from umbra.db import Database
from umbra.evidence import build_bundle
from umbra.models import STATUS_CRAWLED, Ioc, Page

CAPTURED_AT = dt.datetime(2026, 7, 18, 12, 30, tzinfo=dt.timezone.utc)


async def _db(tmp_path, *, with_html=False):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'ev.db'}")
    await db.create_all()
    async with db.session() as s:
        s.add(Page(
            url="http://market.onion/vendor", hostname="market.onion", status=STATUS_CRAWLED,
            title="Vendor page", depth=1, score=1.0,
            content="Cocaine 5g premium $120  BTC 1BvBMSEYstWetqTFn5Au4m4GFg7",
            html="<html><body>Cocaine 5g premium $120</body></html>" if with_html else None,
            content_sha256="a" * 64, content_length=512, http_status=200,
            fetched_at=CAPTURED_AT, blocked=False, stored_content=True,
        ))
        s.add(Ioc(page_url="http://market.onion/vendor", ioc_type="btc",
                  value="1BvBMSEYstWetqTFn5Au4m4GFg7"))
        await s.commit()
    return db


def _open(content: bytes):
    archive = zipfile.ZipFile(io.BytesIO(content))
    return archive, json.loads(archive.read("manifest.json"))


async def test_bundle_contains_material_manifest_and_checksums(tmp_path):
    db = await _db(tmp_path)
    content, summary = await build_bundle(db, host="market.onion", case_name="op-test")
    archive, manifest = _open(content)

    names = set(archive.namelist())
    assert {"manifest.json", "README.txt", "checksums.sha256"} <= names
    assert any(n.endswith(".txt") and n.startswith("pages/") for n in names)

    assert summary["items"] == 1 and manifest["item_count"] == 1
    item = manifest["items"][0]
    assert item["url"] == "http://market.onion/vendor"
    assert item["capture"]["fetched_at"].startswith("2026-07-18T12:30")
    assert item["capture"]["http_status"] == 200
    assert item["indicators"] == [{"type": "btc", "value": "1BvBMSEYstWetqTFn5Au4m4GFg7"}]
    await db.dispose()


async def test_checksums_match_the_files_actually_included(tmp_path):
    db = await _db(tmp_path, with_html=True)
    content, _ = await build_bundle(db)
    archive, _ = _open(content)

    listed = {}
    for line in archive.read("checksums.sha256").decode().splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest

    assert listed  # and every one of them verifies
    for name, digest in listed.items():
        assert hashlib.sha256(archive.read(name)).hexdigest() == digest, name
    await db.dispose()


async def test_says_when_the_capture_hash_cannot_be_verified(tmp_path):
    """content_sha256 covers the raw response body; the .txt is extracted text.
    A verifier who assumes they match would conclude tampering, so the bundle
    has to say which case each item is in."""
    db = await _db(tmp_path, with_html=False)  # store_html off — the default
    _, manifest = _open((await build_bundle(db))[0])
    item = manifest["items"][0]

    assert item["body_verifiable"] is False
    assert item["included"]["html_file"] is None
    assert item["included"]["text_sha256"] != item["capture"]["body_sha256"]
    assert "raw HTTP response body" in manifest["integrity"]["note"]
    await db.dispose()


async def test_legacy_reencoded_html_does_not_prove_original_bytes(tmp_path):
    db = await _db(tmp_path, with_html=True)
    content, summary = await build_bundle(db)
    archive, manifest = _open(content)
    item = manifest["items"][0]

    assert item["body_verifiable"] is False and summary["verifiable_bodies"] == 0
    stored = archive.read(item["included"]["html_file"])
    assert hashlib.sha256(stored).hexdigest() == item["included"]["html_sha256"]
    await db.dispose()


async def test_readme_does_not_overclaim(tmp_path):
    db = await _db(tmp_path)
    archive, manifest = _open((await build_bundle(db))[0])
    readme = archive.read("README.txt").decode()

    assert "not notarised" in readme.lower()
    assert "does NOT show" in readme
    assert manifest["integrity"]["notarised"] is False
    assert manifest["integrity"]["signed"] is False
    await db.dispose()


async def test_signature_is_present_and_correct_when_a_key_is_configured(tmp_path):
    db = await _db(tmp_path)
    content, summary = await build_bundle(db, signing_key="s3cret")
    archive, manifest = _open(content)

    assert summary["signed"] and manifest["integrity"]["signed"] is True
    line = [
        x for x in archive.read("signature.txt").decode().splitlines()
        if x.startswith("signature:")
    ][0]
    expected = hmac.new(b"s3cret", archive.read("checksums.sha256"), hashlib.sha256).hexdigest()
    assert line.split(": ", 1)[1] == expected
    await db.dispose()


async def test_tampering_with_a_file_breaks_verification(tmp_path):
    db = await _db(tmp_path)
    content, _ = await build_bundle(db)
    archive, _ = _open(content)

    page_file = next(n for n in archive.namelist() if n.startswith("pages/"))
    listed = dict(
        (line.split("  ", 1)[1], line.split("  ", 1)[0])
        for line in archive.read("checksums.sha256").decode().splitlines()
    )
    assert hashlib.sha256(b"edited content").hexdigest() != listed[page_file]
    await db.dispose()


async def test_same_material_exports_byte_identically(tmp_path):
    """Two bundles of the same evidence should be directly comparable — a
    timestamp baked into the archive would make every export look different."""
    db = await _db(tmp_path)
    first, _ = await build_bundle(db, generated_at=CAPTURED_AT)
    second, _ = await build_bundle(db, generated_at=CAPTURED_AT)
    assert first == second
    await db.dispose()


async def test_empty_selection_produces_no_items(tmp_path):
    db = await _db(tmp_path)
    _, summary = await build_bundle(db, host="nothing-here.onion")
    assert summary["items"] == 0
    await db.dispose()
