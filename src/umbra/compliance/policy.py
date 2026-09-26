"""Ingest-time compliance gate.

**Design principle:** the crawler must be able to run without accumulating
illegal material on disk. This gate runs *before* anything is persisted and
decides whether raw content may be stored at all.

- **Media** (images/video/audio/binaries) is never decoded or stored as bytes by
  default — only a hash + metadata are kept.
- **Blocklisted categories** are supplied by the *operator* via a plain-text file
  of ``category:regex`` rules (``UMBRA_BLOCKLIST_PATH``). This module ships with
  **no** such rules baked in. When a page matches a category, its content is
  **discarded**; only the URL, a hash, and the matched category name are retained,
  so the event can be audited/reported without the material ever being stored.

This is deliberately conservative: the tool is built to *avoid* collecting the
worst content, not to gather it. Tune the policy — and take legal advice — before
any production deployment.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# Content-type prefixes treated as media / binary — never stored as bytes.
MEDIA_CONTENT_TYPES = (
    "image/",
    "video/",
    "audio/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/x-",
)


@dataclass
class ComplianceDecision:
    store_content: bool
    blocked: bool
    reason: str | None = None
    categories: list[str] = field(default_factory=list)


class CompliancePolicy:
    def __init__(
        self,
        *,
        store_text: bool = True,
        store_html: bool = False,
        store_media: bool = False,
        blocklist: list[tuple[str, re.Pattern[str]]] | None = None,
        known_bad_hashes: set[str] | None = None,
    ) -> None:
        self.store_text = store_text
        self.store_html = store_html
        self.store_media = store_media
        self._rules = blocklist or []
        self._known_bad_hashes = known_bad_hashes or set()

    @classmethod
    def from_file(
        cls, path: str | None, known_bad_hashes_path: str | None = None, **kwargs
    ) -> "CompliancePolicy":
        """Load ``category:regex`` rules from ``path`` (one per line; ``#`` comments)
        and known-bad content hashes from ``known_bad_hashes_path`` (one hex
        SHA-256 per line). Missing paths => empty (media policy still applies).
        """
        rules: list[tuple[str, re.Pattern[str]]] = []
        if path:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    category, pattern = line.split(":", 1)
                    rules.append((category.strip(), re.compile(pattern.strip(), re.I)))

        hashes: set[str] = set()
        if known_bad_hashes_path:
            with open(known_bad_hashes_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        hashes.add(line.split()[0])
        return cls(blocklist=rules, known_bad_hashes=hashes, **kwargs)

    def evaluate(
        self,
        url: str,
        text: str | None,
        content_type: str | None,
        content_sha256: str | None = None,
    ) -> ComplianceDecision:
        # Known-bad hash (CSAM / known malware): hard drop regardless of type.
        # Content is never stored; only the hash + flag remain for audit.
        if content_sha256 and content_sha256.lower() in self._known_bad_hashes:
            return ComplianceDecision(
                store_content=False, blocked=True, reason="known-bad-hash",
                categories=["known-bad-hash"],
            )

        ctype = (content_type or "").lower()
        if any(ctype.startswith(prefix) for prefix in MEDIA_CONTENT_TYPES):
            return ComplianceDecision(store_content=self.store_media, blocked=False, reason="media")

        haystack = f"{url}\n{text or ''}"
        matched = [cat for cat, rx in self._rules if rx.search(haystack)]
        if matched:
            # Hard stop: never persist the body of a blocklisted page.
            return ComplianceDecision(
                store_content=False, blocked=True, reason="blocklist", categories=matched
            )

        return ComplianceDecision(store_content=True, blocked=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
