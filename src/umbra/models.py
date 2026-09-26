"""SQLAlchemy 2.0 ORM models.

Two tables to start: ``pages`` (the crawl frontier/result) and ``iocs``
(enrichment output). The schema is Postgres-friendly; on SQLite it just works too.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, column_property
from .run_context import current_run


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


# Page lifecycle states.
STATUS_DISCOVERED = "discovered"    # known, not yet fetched
STATUS_IN_PROGRESS = "in_progress"  # claimed by a worker, fetch in flight
STATUS_CRAWLED = "crawled"          # fetched and parsed successfully
STATUS_DEAD = "dead"                # fetch failed / unreachable
STATUS_BLOCKED = "blocked"          # fetched but content withheld by compliance policy


class Page(Base):
    __tablename__ = "pages"

    url: Mapped[str] = mapped_column(String(2048), primary_key=True)
    parent_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    # A seed the operator chose as a *target* (a source pack entry, a specific
    # market) rather than a place to discover other sites from. Links leading
    # off a pinned host are demoted and the host gets a larger page budget —
    # measured, off-host links from targeted seeds were 93-96% noise at every
    # depth while going deeper into the same host was the best signal there was.
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    # Inherited down the discovery tree from a pinned seed. Says which *mode*
    # this page was reached in: a targeted lineage demotes every link that
    # leaves a pinned host, however many hops out it is found; an untargeted
    # one (a directory or wiki seed) never does. Without this the demotion
    # applied only to a pinned host's immediate children, and a page reached
    # via one off-host hop handed out full-priority links to a second — on a
    # live frontier that left 71% of the next pass off-target.
    targeted: Mapped[bool] = mapped_column(Boolean, default=False)

    status: Mapped[str] = mapped_column(String(16), default=STATUS_DISCOVERED, index=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)

    title: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    keywords: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Enrichment output (LLM classification/summary — see enrich/llm.py).
    page_type: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    threat_category: Mapped[str | None] = mapped_column(String(48), index=True, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Content is optional and governed by the compliance policy. Even when the
    # body is withheld, we always keep the hash so a finding can be referenced
    # for audit/reporting without retaining the material itself.
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    html: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    capture_metadata: Mapped[str | None] = mapped_column(Text)
    extraction_errors: Mapped[str | None] = mapped_column(Text)
    body_truncated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    final_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    content_sha256: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stored_content: Mapped[bool] = mapped_column(Boolean, default=False)

    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    block_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    fetched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    content_captured_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    processing_failures: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Recrawl scheduling (freshness). A page is eligible to (re)crawl when
    # next_crawl_at <= now. The interval adapts: it doubles when content is
    # unchanged and resets when it changes, so stable pages are polled less.
    next_crawl_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    claimed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Monotonic ownership token, bumped on every claim. Used as an exact-match
    # claim check on completion (datetimes don't round-trip exactly on SQLite).
    claim_seq: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    recrawl_interval_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_changed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Page {self.status} {self.url!r}>"


class Ioc(Base):
    """An indicator/entity extracted from a page (crypto address, PGP key, CVE, …)."""

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    page_url: Mapped[str] = mapped_column(String(2048), index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_ioc_type_value", "ioc_type", "value"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Ioc {self.ioc_type}={self.value!r}>"


class Embedding(Base):
    """A dense vector for a page's text, enabling semantic ("find pages like…")
    search. Stored as raw float32 bytes; on Postgres this is the migration point
    to pgvector for indexed nearest-neighbour at scale.
    """

    __tablename__ = "embeddings"
    __table_args__ = (Index("ix_embedding_model_dim_url", "model", "dim", "page_url"),)

    page_url: Mapped[str] = mapped_column(String(2048), primary_key=True)
    model: Mapped[str] = mapped_column(String(64))
    dim: Mapped[int] = mapped_column(Integer)
    vector: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Credential(Base):
    """A leaked credential found on a page. The plaintext password is NEVER
    stored — only a SHA-256 — so the corpus is a breach-lookup index, not a
    password store. Customers match by email/domain (+ optional hash check).
    """

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    page_url: Mapped[str] = mapped_column(String(2048), index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    password_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_cred_email_domain", "email", "domain"),)


class Listing(Base):
    """A marketplace listing extracted from a page (vendor / product / price)."""

    __tablename__ = "listings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    page_url: Mapped[str] = mapped_column(String(2048), index=True)
    product: Mapped[str | None] = mapped_column(String(512), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    price: Mapped[float | None] = mapped_column(Float, nullable=True)
    currency: Mapped[str | None] = mapped_column(String(16), nullable=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Actor(Base):
    """A resolved threat actor — a cluster of identifiers (PGP key, crypto
    address, handle) linked across pages by entity resolution.
    """

    __tablename__ = "actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(255))
    page_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActorIdentifier(Base):
    """One identifier (e.g. a PGP key or BTC address) belonging to an actor."""

    __tablename__ = "actor_identifiers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[int] = mapped_column(Integer, index=True)
    ioc_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(512), index=True)

    __table_args__ = (Index("ix_actorident_type_value", "ioc_type", "value"),)


class Watchlist(Base):
    """A saved query evaluated against new/changed pages; matches raise alerts."""

    __tablename__ = "watchlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(16))  # keyword | ioc | domain | email
    value: Mapped[str] = mapped_column(String(512))
    webhook_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    """A watchlist match (the alerting audit trail).

    ``dedup_key`` is what stops the same fact alerting twice, and what it means
    depends on the watchlist. For a content watchlist it is the page URL — the
    keyword being on that page is one fact however many times it is re-matched.
    For an event watchlist it is the event, because a service going down, coming
    back, and going down again is genuinely three things worth telling someone
    about, and keying those on the page would silently suppress all but the first.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    watchlist_id: Mapped[int] = mapped_column(Integer, index=True)
    page_url: Mapped[str] = mapped_column(String(2048), index=True)
    matched_value: Mapped[str] = mapped_column(String(512))
    dedup_key: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    event_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_alert_watch_dedup", "watchlist_id", "dedup_key", unique=True),
    )


class Event(Base):
    """One entry in the intelligence timeline: something changed in the world.

    Every other table stores the *current* state of the dark web. Recrawling
    overwrites it — a page's new content replaces the old, a vendor's new wallet
    replaces the last one — so the moment a change happens is also the moment the
    evidence of it is destroyed. This table is the only place that history
    survives, and history is most of what an analyst is actually paid to notice:
    a market going quiet is an exit scam or a takedown, a vendor's PGP key
    changing is either a compromise or an impersonator.

    ``page_url`` is intentionally a plain column, not a foreign key: events must
    outlive the pages they describe, or retention purges would erase exactly the
    long-range history the timeline exists to provide. Events carry no page
    content — only metadata about a transition — so they are safe to keep after a
    page is dropped for policy or retention reasons.
    """

    __tablename__ = "events"
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True,
                                             default=lambda: current_run.get())

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    page_url: Mapped[str | None] = mapped_column(String(2048), index=True, nullable=True)
    summary: Mapped[str] = mapped_column(String(512))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_event_kind_time", "kind", "occurred_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Event {self.kind} {self.page_url!r}>"


class Run(Base):
    """One collection pass, recorded whether it succeeded, failed, or did nothing.

    Collection failing silently is the worst outcome this system has: the data
    just stops arriving and every dashboard still looks fine, because a view of
    stored intelligence cannot distinguish "nothing happened out there" from
    "we stopped looking". That is not hypothetical — a budget bug left the worker
    fetching nothing for a whole cycle while logging the previous pass's totals,
    and only a by-eye comparison of two log lines caught it.

    ``queued_at_start`` and ``due_at_start`` exist to separate the two reasons a
    pass can crawl nothing. A drained frontier with nothing due is a healthy idle
    pass; crawling nothing while work was waiting is a stall. Without that
    snapshot the distinction is unrecoverable after the fact, and an alarm that
    cannot tell them apart is one people learn to ignore.
    """

    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|ok|error
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    processing_errors: Mapped[int] = mapped_column(Integer, default=0)
    trigger: Mapped[str] = mapped_column(String(16), default="worker")  # worker|cli|api
    pages_crawled: Mapped[int] = mapped_column(Integer, default=0)
    pages_dead: Mapped[int] = mapped_column(Integer, default=0)
    iocs_found: Mapped[int] = mapped_column(Integer, default=0)
    events_emitted: Mapped[int] = mapped_column(Integer, default=0)
    new_alerts: Mapped[int] = mapped_column(Integer, default=0)
    actors: Mapped[int] = mapped_column(Integer, default=0)
    queued_at_start: Mapped[int] = mapped_column(Integer, default=0)
    due_at_start: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Run {self.id} {self.status} crawled={self.pages_crawled}>"


class ApiKey(Base):
    """An API key for the query service."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # viewer | admin
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PageVersion(Base):
    """Retained capture; bytes are HTTP content-decoded, before character decoding."""
    __tablename__ = "page_versions"
    __table_args__ = {"sqlite_autoincrement": True}
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    page_url: Mapped[str] = mapped_column(String(2048), index=True)
    captured_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    title: Mapped[str | None] = mapped_column(String(1024))
    content: Mapped[str | None] = mapped_column(Text)
    raw_body: Mapped[bytes | None] = mapped_column(LargeBinary)
    capture_metadata: Mapped[str | None] = mapped_column(Text)
    body_sha256: Mapped[str | None] = mapped_column(String(64))
    body_truncated: Mapped[bool | None] = mapped_column(Boolean)
    final_url: Mapped[str | None] = mapped_column(String(2048))
    http_status: Mapped[int | None] = mapped_column(Integer)
    legacy: Mapped[bool] = mapped_column(Boolean, default=False)


PageVersion.body_available = column_property(PageVersion.raw_body.is_not(None))


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    assigned_to: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaseItem(Base):
    __tablename__ = "case_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(Integer, index=True)
    page_url: Mapped[str] = mapped_column(String(2048))
    version_id: Mapped[int] = mapped_column(Integer, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str] = mapped_column(String(16), default="unreviewed")
    __table_args__ = (Index("ix_case_version", "case_id", "version_id", unique=True),)


class CaseActivity(Base):
    __tablename__ = "case_activity"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RelationshipReview(Base):
    """Stable identifier pair; survives cluster rebuilds and numeric ID changes."""
    __tablename__ = "relationship_reviews"
    pair_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    left_type: Mapped[str] = mapped_column(String(32))
    left_value: Mapped[str] = mapped_column(String(512))
    right_type: Mapped[str] = mapped_column(String(32))
    right_value: Mapped[str] = mapped_column(String(512))
    verdict: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    reviewer: Mapped[str] = mapped_column(String(255))
    reviewed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserAccount(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(Text)
    totp_pending: Mapped[str | None] = mapped_column(Text)
    totp_last_step: Mapped[int | None] = mapped_column(Integer)


class RecoveryToken(Base):
    __tablename__ = "recovery_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class CollectionJob(Base):
    __tablename__ = "collection_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    config: Mapped[str] = mapped_column(Text)
    interval_s: Mapped[int] = mapped_column(Integer, default=0)
    paused: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    claim_seq: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="paused")
    last_result: Mapped[str] = mapped_column(Text, default="{}")
    stop_reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExtractionFeedback(Base):
    __tablename__ = "extraction_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    page_url: Mapped[str] = mapped_column(String(2048), index=True)
    version_id: Mapped[int] = mapped_column(Integer)
    extractor: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(1024))
    verdict: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    reviewer: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class CaseMember(Base):
    __tablename__ = "case_members"
    case_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    permission: Mapped[str] = mapped_column(String(16), default="read")


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    at: Mapped[str] = mapped_column(String(64))


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    query: Mapped[str] = mapped_column(Text)


class AlertReview(Base):
    __tablename__ = "alert_reviews"
    alert_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="new")
    assigned_to: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
