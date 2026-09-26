# Changelog

Each release lists what changed and how it was checked. "Validated" means an
automated test or a recorded manual check; claims that were not validated say so.

## Unreleased: public release preparation

- **Fixed: outages never appeared in the service view or the dashboard.** A
  failed recrawl keeps its page `crawled` so the archived content survives, and
  liveness counted status alone, so a service that went dark still showed as up
  and "Unreachable" read 0. All reachability views now share one definition
  (`timeline.not_answering()`). Found by the synthetic demo lab; regression-tested.
- **Added `scripts/demo_lab.py`:** the real pipeline over a fictional site
  graph, with no Tor and no network. Two recorded passes produce genuine
  timeline transitions (a shop going dark, a vendor rotating keys).
- **Replaced the bundled source packs** with a single `getting-started` pack of
  public organisations' onion services, each verified reachable over Tor with a
  matching page title before inclusion. Operator packs load from
  `UMBRA_SOURCE_PACKS_PATH`. A test guards against anything else being bundled.
- Test fixtures derived from real crawls were replaced with synthetic values.
- UI: long onion names truncate instead of overflowing their panels; the
  Timeline's highlighted button reflects the active view.
- Licensed under MIT.

## 0.4.1: pilot hardening

- Individual-session-only mode: anonymous and shared-key access are rejected
  when enabled. Case exports recheck membership after the bundle is built.
- Sensitive responses send `no-store`, `no-referrer`, `nosniff` and frame denial.
- A guided administrator setup enrols MFA before enabling restricted mode. A
  readiness check reports storage thresholds before each collection session.
- Validated: the installed wheel in a fresh Python 3.12 environment on a separate
  Linux host (API, anonymous denial, GUI assets, encrypted restore); a
  dependency vulnerability scan; the full suite. Not validated: a 48-hour
  endurance run (interrupted at 20 hours) and representative live extraction accuracy.

## 0.4.0: investigation workflow and durable collection

- **Persistent jobs:** named, saved collection with seeds, host restriction,
  depth, page and time budgets, and a repeat interval. A database lease
  serialises jobs across API processes, and stale owners are fenced out.
- **Collection quality view:** unique complete bodies, duplicate rate,
  freshness, extraction failures and unknown metadata.
- **Independent evidence verification:** exports include `verify_evidence.py`,
  standard-library only, which checks member names, coverage, checksums,
  manifest claims and retained body hashes, plus HMAC if a key is supplied.
  Captures record collector version, settings and extractor names.
- **Extraction:** listings are read from table rows and product cards; legacy
  Base58 Bitcoin addresses must pass their checksum. Analysts can record
  correct, false-positive and missed extractions against a specific version,
  exportable as regression examples.
- **Security:** optional TOTP MFA with replay protection; single-use,
  15-minute recovery tokens that preserve MFA and revoke sessions; streaming
  AES-256-GCM encrypted backups; an authenticated restore.
- **Schema:** revision 004 adopts existing databases, serialises migrations and
  refuses unsupported newer revisions. PostgreSQL gains an append-only audit
  trigger and a dedicated integration test, which runs in CI.
- The navigation follows the workflow: Collect → Review → Investigate → Report.

## 0.3.0: investigator workspace

- Exact-duplicate and mirror grouping across hosts.
- Guided collection presets ("monitor these sites" and "directory discovery"),
  with a scope preview and a Tor readiness check.
- Full-text search (SQLite FTS5) with phrases, exclusions and filters, plus
  personal saved searches.
- An evidence-linked identifier graph with snippets and pivots.
- Case reports: a printable chronology separating source observations from
  analyst interpretation, with literal redaction and a report digest in the audit log.
- Individual accounts with administrator, analyst and viewer roles; case
  membership; eight-hour sessions with immediate revocation; hash-linked audit history.
- Alert triage (acknowledge, assign, resolve). Markup-only changes don't raise
  content alerts.
- One-click startup; verified-process stop and restart; SQLite backup with an
  integrity check; restore to a new file only.

## 0.2.0: reliability

- Raw HTTP bodies can be retained, so evidence hashes verify against the exact
  bytes. Truncation is recorded, and up to 20 versions are kept per page.
- Strict scope applies to discovery, queued claims and **every redirect**.
- Semantic search reads vectors in bounded batches instead of loading the corpus.
- Frontier writes use SQLite write reservations or PostgreSQL advisory locks.
  Page leases have heartbeats, and stale or duplicate completions are rejected.
  Processing errors have their own bounded retry counter.
- Discovery inserts are batched. CPU work runs off the event loop.
- Cases with exhibits and notes; exports record their hash and exporter.
- A labelled synthetic extraction benchmark reports precision and recall.
- Analyst-reviewed relationships: confirm or reject links with a reason. A
  rejection blocks indirect merges and survives graph rebuilds.
- Validated: independent SQLite engines contending for claims, a real
  child-process crash, lease renewal, redirect blocking, trickling responses,
  stale completion and cancellation.

## 0.1.0: the rebuild

A ground-up replacement for the original university crawler. That project
shared one database session across threads, patched the process-wide socket
for Tor, and kept its frontier in memory.

- A single asyncio loop with a session per unit of work; a Tor SOCKS proxy
  scoped to one HTTP client; streamed downloads with byte caps.
- A database-backed, resumable frontier with adaptive recrawl and failure
  backoff that never destroys previously archived content.
- A compliance gate at ingest: no media, operator blocklists, known-bad hash
  drop, and credentials stored only as hashes.
- Extraction of wallets, PGP fingerprints computed from armoured keys, operator
  contacts distinct from breach victims, credentials and listings.
  Entity resolution clusters actors on shared identifiers.
- A change-and-outage timeline; per-pass run health (idle, stalled, stale,
  failing); event-driven watchlists with webhooks.
- Semantic search with a local ONNX embedder and a hashing fallback.
- STIX 2.1 export with deterministic IDs; evidence bundles.
- Hardening: SSRF guard on webhooks and non-Tor fetches, including redirects;
  a network-bound API never starts unauthenticated; LLM output cannot create
  actor-linking identifiers.
- Found by running it, and fixed: a worker that silently stopped collecting
  after one pass; a health banner that stayed green with the worker dead; a
  malformed link that aborted pages and looped forever; a scorer change
  invisible to the existing frontier; an actor graph that never rebuilt.
