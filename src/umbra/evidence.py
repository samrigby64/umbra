"""Evidence bundles — stored pages packaged for use in an investigation.

An analyst who finds something in this system eventually has to show it to
someone else: a client, a regulator, a court. That needs the material plus the
circumstances of its capture — what was fetched, when, and what it hashed to at
the time.

**What this does and does not establish, stated plainly**, because an evidence
feature that overclaims is worse than none:

* It **does** record what was captured, when, and the hash observed at capture,
  and lets anyone recompute the hashes of the files in the bundle.
* It **does not** prove the content is what the server actually served. Nothing
  here is notarised or timestamped by a third party, and with no signing key
  configured a bundle proves internal consistency only — anyone able to edit the
  files can regenerate the checksums.
* Critically, ``content_sha256`` is the hash of the **HTTP content-decoded body bytes**,
  while the text in the bundle is *extracted* from it. Those are different
  artifacts and will not match, which is expected, not evidence of tampering.
  The raw body can only be included when ``store_html`` is enabled — and for
  investigation work it should be, because without it the capture-time hash
  cannot be checked against anything at all. Each item says which case it is in.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import io
import json
import re
import zipfile
from pathlib import Path
from types import SimpleNamespace

import sqlalchemy as sa

from .db import Database
from .logging import get_logger
from .models import Ioc, Page, PageVersion

log = get_logger("evidence")

TOOL = "umbra"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(url: str, index: int) -> str:
    tail = _SAFE.sub("-", url.split("://", 1)[-1])[:60].strip("-")
    return f"{index:04d}-{tail or 'page'}"


def _iso(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:  # SQLite drops tzinfo on round-trip
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat()


async def build_bundle(
    db: Database,
    host: str | None = None,
    url: str | None = None,
    limit: int = 200,
    case_name: str | None = None,
    signing_key: str | None = None,
    generated_at: dt.datetime | None = None,
    version_ids: list[int] | None = None,
    case_metadata: dict | None = None,
) -> tuple[bytes, dict]:
    """Build a ZIP of captured pages plus a manifest. Returns (zip bytes, summary)."""
    async with db.session() as session:
        stmt = sa.select(Page).where(Page.blocked.is_(False), Page.content.isnot(None))
        if url:
            stmt = stmt.where(Page.url == url)
        if host:
            stmt = stmt.where(Page.hostname == host)
        pages = [] if version_ids is not None else (
            await session.execute(stmt.order_by(Page.url).limit(limit))
        ).scalars().all()
        if version_ids is not None:
            versions = (await session.execute(sa.select(PageVersion).where(
                PageVersion.id.in_(version_ids)
            ).order_by(PageVersion.id).limit(limit))).scalars().all()
            pages = [SimpleNamespace(
                url=v.page_url, hostname=v.page_url.split('/')[2], title=v.title,
                content=v.content, html=None, raw_body=v.raw_body,
                content_sha256=v.body_sha256,
                content_length=len(v.raw_body) if v.raw_body is not None else None,
                fetched_at=v.captured_at, created_at=None, content_changed_at=None,
                http_status=v.http_status, body_truncated=v.body_truncated,
                final_url=v.final_url, version_id=v.id, legacy=v.legacy,
                capture_metadata=v.capture_metadata,
            ) for v in versions]

        urls = [p.url for p in pages]
        iocs: dict[str, list[dict]] = {}
        if urls and version_ids is None:
            for ioc in (
                await session.execute(sa.select(Ioc).where(Ioc.page_url.in_(urls)))
            ).scalars():
                iocs.setdefault(ioc.page_url, []).append(
                    {"type": ioc.ioc_type, "value": ioc.value}
                )

    stamp = generated_at or dt.datetime.now(dt.timezone.utc)
    files: dict[str, bytes] = {}
    items: list[dict] = []

    for index, page in enumerate(pages, start=1):
        base = _safe_name(page.url, index)
        text_bytes = (page.content or "").encode("utf-8")
        text_path = f"pages/{base}.txt"
        files[text_path] = text_bytes

        html_path = None
        if page.html:
            html_path = f"pages/{base}.html"
            files[html_path] = page.html.encode("utf-8")
        body_path = None
        if page.raw_body is not None:
            body_path = f"pages/{base}.body"
            files[body_path] = page.raw_body
        verified = bool(body_path and _sha256(files[body_path]) == page.content_sha256)

        items.append({
            "url": page.url,
            "hostname": page.hostname,
            "title": page.title,
            "version_id": getattr(page, "version_id", None),
            "legacy": getattr(page, "legacy", False),
            "capture": {
                "collector": json.loads(page.capture_metadata) if page.capture_metadata else None,
                "fetched_at": _iso(getattr(page, "content_captured_at", None) or page.fetched_at),
                "timestamp_source": ("retained_version" if version_ids is not None else
                    "successful_capture" if getattr(page, "content_captured_at", None) else
                    "legacy_last_fetch_unverified"),
                "first_seen": _iso(page.created_at),
                "content_changed_at": _iso(page.content_changed_at),
                "http_status": page.http_status,
                "content_length": page.content_length,
                # Hash of the RAW RESPONSE BODY as observed at capture time.
                "body_sha256": page.content_sha256,
                "truncated": page.body_truncated,
                "final_url": page.final_url,
                "byte_representation": "HTTP content-decoded bytes before character decoding",
            },
            "included": {
                "text_file": text_path,
                "text_sha256": _sha256(text_bytes),
                "html_file": html_path,
                "html_sha256": _sha256(files[html_path]) if html_path else None,
                "body_file": body_path,
            },
            # Says outright whether the capture hash can be checked against
            # anything in this bundle, rather than leaving a verifier to discover
            # the mismatch and draw the wrong conclusion.
            "body_verifiable": verified,
            "complete_body_verifiable": verified and page.body_truncated is False,
            "indicators": iocs.get(page.url, []),
        })

    manifest = {
        "tool": TOOL,
        "bundle_version": "1.2",
        "case": case_name or (host or url or "all"),
        "generated_at": _iso(stamp),
        "query": {"host": host, "url": url, "limit": limit},
        "item_count": len(items),
        "integrity": {
            "hash_algorithm": "sha256",
            "signed": bool(signing_key),
            "notarised": False,
            "note": (
                "capture.body_sha256 describes the captured raw HTTP response body "
                "after content decoding, before character decoding. Verify the .body "
                "file, not re-encoded .html. A truncated capture verifies only a prefix; "
                "null truncation means unknown for legacy data. No trusted timestamp."
            ),
        },
        "items": items,
        "case_metadata": case_metadata,
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    files["manifest.json"] = manifest_bytes
    files["README.txt"] = ("""UMBRA EVIDENCE BUNDLE 1.1
Contents: manifest.json, checksums.sha256, pages/*.txt (extracted text),
pages/*.html (decoded and re-encoded HTML), pages/*.body (captured body bytes).
Verify: sha256sum -c checksums.sha256
body_verifiable is true only when retained .body bytes match the capture hash.
These are HTTP content-decoded bytes, not wire packets or compressed transport bytes.
truncated=true verifies only the retained prefix. null means legacy/unknown.
Historical versions include no current indicators masquerading as historical ones.
What this does NOT show: identity of a site operator or authenticity of its claims.
This is not notarised and has no third-party timestamp. Checksums alone can be
regenerated by an editor. Optional HMAC requires a separately protected secret;
it is not a public-key signature or proof of legal chain of custody.
""").encode("utf-8")

    files["verify_evidence.py"] = Path(__file__).with_name("verify_evidence.py").read_bytes()
    files["README.txt"] += (
        "\nOffline verification (Python 3, no Umbra dependencies):\n"
        "python verify_evidence.py bundle.zip\n"
        "Use --key-file protected-key.txt to authenticate an HMAC-signed bundle.\n"
        "Obtain a trusted verifier separately; a bundled script can itself be replaced.\n"
    ).encode()
    checksums = "".join(
        f"{_sha256(data)}  {name}\n" for name, data in sorted(files.items())
    ).encode("utf-8")
    files["checksums.sha256"] = checksums

    if signing_key:
        # HMAC over the checksum list, so it covers every file transitively.
        # Without the key a bundle is integrity-only; with it, edits are
        # detectable by anyone holding the key. Not a substitute for notarisation.
        signature = hmac.new(signing_key.encode("utf-8"), checksums, hashlib.sha256).hexdigest()
        files["signature.txt"] = (
            f"algorithm: HMAC-SHA256\nover: checksums.sha256\nsignature: {signature}\n"
        ).encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            # Fixed timestamp so the same evidence exports byte-identically and
            # two bundles of the same material can be compared directly.
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, files[name])

    summary = {
        "items": len(items),
        "verifiable_bodies": sum(1 for i in items if i["body_verifiable"]),
        "signed": bool(signing_key),
        "bytes": buffer.tell(),
    }
    log.info("evidence bundle: %s", summary)
    return buffer.getvalue(), summary
