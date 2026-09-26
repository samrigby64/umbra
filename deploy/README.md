# Deploying Umbra

`docker compose up` brings up the whole platform: a Tor SOCKS proxy, Postgres, the
query/alerting **API**, and a continuously-running crawler **worker**.

```
tor ──SOCKS──┐
             ▼
  worker ──▶ postgres ◀── api ──▶ :8000  (your analysts / apps)
  (crawl → extract → alert → recrawl, forever)
```

## Quick start

```bash
cd umbra
docker compose up -d --build        # builds the image, starts everything
```

The `init` service creates the schema, then `api` (on :8000) and `worker` start.

```bash
# 1. Get the bootstrap admin key. The API never runs open on a network bind:
#    if no key exists at first start, one is minted and printed ONCE to the log.
docker compose logs api | grep -A3 "bootstrap admin key"
#    Then create your own and revoke the bootstrap one:
docker compose run --rm api apikey --name ops --role admin
docker compose run --rm api apikey-revoke bootstrap-admin
docker compose run --rm api apikey-list

# 2. Start from a source pack (curated coverage), or add your own seed URLs
docker compose run --rm api sources                      # list packs
docker compose run --rm api sources --seed getting-started   # safe example pack
$EDITOR deploy/seeds.txt                                 # and/or your own
docker compose restart worker

# 3. Add a watchlist (alerts POST to your webhook after each crawl pass)
docker compose run --rm api watch domain acme.com --webhook https://hooks.example.com/umbra

# 4. Query the API
curl -H "X-API-Key: <KEY>" "http://localhost:8000/search?q=stolen%20cards"
curl -H "X-API-Key: <KEY>" "http://localhost:8000/actors"
open http://localhost:8000/docs        # interactive API docs
```

## Operating it

```bash
docker compose logs -f worker          # watch crawl progress
docker compose run --rm api runs       # is collection actually doing anything?
docker compose run --rm api timeline --notable   # outages, recoveries, new identifiers
docker compose run --rm api purge --days 90  # apply retention now
docker compose down                    # stop (Postgres data persists in the volume)
```

The dashboard at `http://localhost:8000/` shows the same collection-health verdict
(`ok` / `idle` / `stalled` / `failing`) above the counts. The counts alone cannot
tell you collection has stopped — the verdict can.

## Backups

**The database is the product.** Everything else is rebuildable from it; nothing
rebuilds it. Back it up on a schedule from day one:

```bash
docker compose exec postgres pg_dump -U umbra umbra | gzip > umbra-$(date +%F).sql.gz
```

For a non-Docker install on SQLite, the file lives under the per-user data
directory (`%LOCALAPPDATA%\umbra\umbra.db` on Windows, `~/.local/share/umbra/`
elsewhere). Copy it with `sqlite3 umbra.db ".backup umbra-backup.db"` rather than
a raw file copy, which can catch a WAL mid-write.

## Before production

- **Change the Postgres password** in `docker-compose.yml` (and use a secret).
- Set `UMBRA_KNOWN_BAD_HASHES_PATH` / `UMBRA_BLOCKLIST_PATH` (mount the files) and
  `UMBRA_RETENTION_DAYS` — see the top-level README's compliance section.
- Put the API behind TLS + your own auth gateway; the built-in API-key check is a
  floor, not a substitute for a real edge.
- Webhook URLs and (when Tor is off) crawl targets are refused if they point at
  private, loopback or link-local addresses, including after redirects. This is a
  floor too: it does not defend against DNS rebinding between check and connect.
- If you will produce **evidence bundles**, set `UMBRA_STORE_HTML=true` and
  `UMBRA_EVIDENCE_SIGNING_KEY`. Without the raw HTML the capture-time hash cannot
  be verified against anything in the bundle; the bundle's README says so.
- The semantic embedder (`[embeddings]`) is in the image and on by default; the
  model is baked in so there is no cold download.
- **Get legal advice before pointing the worker at live onion services.** The
  compliance gate limits what is stored, not whether collection is lawful where
  you operate.
