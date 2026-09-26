"""Central configuration.

Everything is env-overridable (prefix ``UMBRA_``) or via a ``.env`` file, so there
are no hardcoded seed lists or secrets buried in modules like there were in the
original project. Import ``Settings()`` once and pass it down.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _default_database_url() -> str:
    """A per-user data directory — never the working directory.

    A relative ``umbra.db`` means ``umbra serve`` and ``umbra worker`` started
    from different directories silently use different databases. And a demo
    that ran from a temp directory lost six weeks of collection to routine
    cleanup. The database *is* the product; where it lives must not depend on
    where a shell happened to be.
    """
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return f"sqlite+aiosqlite:///{(base / 'umbra' / 'umbra.db').as_posix()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UMBRA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Tor / transport -------------------------------------------------
    use_tor: bool = True  # set False to fetch directly (clearnet test/demo runs)
    tor_socks_host: str = "127.0.0.1"
    tor_socks_port: int = 9050
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"
    )
    request_timeout: float = 60.0
    fetch_retries: int = 2
    max_response_bytes: int = 5_000_000

    # --- Storage ---------------------------------------------------------
    # Dev default is a local SQLite file. For production, set e.g.
    #   UMBRA_DATABASE_URL=postgresql+asyncpg://user:pass@host/umbra
    database_url: str = Field(default_factory=_default_database_url)
    backup_interval_hours: int = Field(default=6, ge=0, le=8760)
    backup_key_file: str | None = None
    security_key_file: str | None = None
    db_echo: bool = False
    preview_mode: bool = False  # isolated synthetic GUI lab; collection disabled
    beta_mode: bool = False  # individual sessions only; no anonymous or shared-key access

    # --- Crawl orchestration --------------------------------------------
    max_workers: int = 8
    max_pages: int = 500
    max_depth: int = 5
    max_pages_per_domain: int = 25
    per_request_delay: float = 0.0  # politeness pause after each fetch (seconds)
    allow_clearnet: bool = False  # if False, only .onion children are enqueued
    allowed_hosts: list[str] = Field(default_factory=list)
    strict_scope: bool = False  # derive exact allowed hosts from seeds when none supplied
    versions_per_page: int = Field(default=20, ge=1, le=1000)

    # --- Focused crawling (extension seam for #2) ------------------------
    # Accepts a comma-separated string OR a JSON list from the env.
    # Empty => uniform priority (breadth-first-ish).
    focus_keywords: Annotated[list[str], NoDecode] = Field(default_factory=list)
    focus_threshold: float = 0.0  # minimum link score required to enqueue
    # Rank links by what the URL *is* (vendor/category up, login/register down)
    # on top of any keyword focus. Disable to get a pure breadth-first frontier.
    structural_priority: bool = True
    # Pinned seeds (source packs, `crawl --pin`, the GUI checkbox) are targets,
    # not jumping-off points. A link from a pinned host to any other host has its
    # priority multiplied by this — demoted to the back of the queue, never
    # dropped — and the pinned host itself gets the larger page budget below.
    # Unpinned seeds (a directory, a wiki) are untouched: there the outbound
    # links are the whole point.
    off_host_priority: float = 0.1
    max_pages_per_domain_pinned: int = 100

    # Optional HMAC key for evidence bundles. Without it a bundle proves internal
    # consistency only — anyone who can edit the files can regenerate the
    # checksums. With it, tampering is detectable by anyone holding the key.
    evidence_signing_key: str | None = None

    # Directory of operator-curated source packs, loaded alongside the bundled
    # ones. Coverage is the part of this product that has to differ per customer,
    # so it lives in data they can edit rather than in the package.
    source_packs_path: str | None = None

    # How long to keep the collection-pass log. Operational telemetry, not
    # intelligence, so it has its own (shorter) lifetime than retention_days —
    # long enough to see a trend, short enough not to grow without bound.
    run_retention_days: int = 30
    # How long collection may go without a completed pass before health reads
    # "stale". A dead worker leaves the last pass "ok" forever; this is what turns
    # that into a warning. Set to comfortably more than the worker interval.
    health_stale_after_s: int = 3600

    @field_validator("focus_keywords", mode="before")
    @classmethod
    def _split_focus_keywords(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):  # tolerate a JSON list too
                import json

                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    pass
            return [k.strip() for k in v.split(",") if k.strip()]
        return v

    # --- Recrawl / freshness --------------------------------------------
    # A crawled page becomes eligible again after this many seconds. On each
    # recrawl the interval adapts (doubles up to _max when content is unchanged,
    # resets to base when it changes). 0 disables recrawl entirely.
    recrawl_interval_s: int = 86_400          # 1 day
    recrawl_interval_max_s: int = 604_800     # 7 days
    # A page claimed by a worker that dies (crash, early stop) is re-claimable
    # after this many seconds, so an interrupted crawl fully recovers on resume.
    reclaim_after_s: int = 300
    # A transient fetch failure is retried with backoff; only after this many
    # consecutive failures is a page marked permanently dead. Previously-crawled
    # content is preserved across failures.
    max_fetch_failures: int = 5

    # --- Compliance (see compliance/policy.py) ---------------------------
    store_text: bool = True   # persist extracted plain text
    store_html: bool = False  # persist raw HTML (off by default — bulkier, riskier)
    store_media: bool = False # never store media bytes by default
    blocklist_path: str | None = None  # operator-supplied "category:regex" file
    # Operator-supplied file of known-bad content SHA-256 hashes (one per line):
    # CSAM/known-malware hash sets. A page whose body hash matches is dropped and
    # its content is never stored — only the hash + flag are kept for audit.
    known_bad_hashes_path: str | None = None
    # Data retention: pages (and their derived records) older than this many days
    # are deleted by `umbra purge`. 0 = keep forever.
    retention_days: int = 0

    # --- Intelligence: LLM enrichment (enrich/llm.py) --------------------
    # Off by default so the core runs with no API key. When enabled, each page
    # is classified/summarised by Claude. Reads ANTHROPIC_API_KEY from the env.
    llm_enabled: bool = False
    llm_model: str = "claude-opus-4-8"   # operators processing high volume often switch to a cheaper tier
    llm_max_chars: int = 12_000          # truncate page text sent to the model
    llm_timeout_s: float = 60.0          # bound each extraction call

    # --- Intelligence: embeddings / semantic search (intel/embeddings.py)
    # "local" is a real semantic model that runs offline on CPU and needs no API
    # key; it falls back to hashing automatically if the [embeddings] extra isn't
    # installed, so this default is safe everywhere.
    #
    # Hashing is a *lexical* approximation and degrades sharply once the corpus
    # vocabulary exceeds the bucket count: measured on a real crawl, 8,215
    # distinct tokens over 256 buckets put ~32 unrelated words in every bucket
    # and scored "narcotics" against a cocaine listing at 0.000 — identical to an
    # unrelated page. 2048 keeps the fallback usable at 8 KB per page.
    embeddings_enabled: bool = True
    embedder_kind: str = "local"         # "local" (real semantics, offline) | "hashing" (zero-setup fallback)
    embedding_dim: int = 2048            # hashing embedder dimension (fallback only)
    local_embedding_model: str = "BAAI/bge-small-en-v1.5"  # for embedder_kind="local"

    # --- Logging ---------------------------------------------------------
    log_level: str = "INFO"
