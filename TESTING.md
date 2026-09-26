# Testing Umbra

**Start with the synthetic demo.** It needs no Tor and touches no network: the
real pipeline runs over a fictional site graph and serves a populated GUI.

```bash
python scripts/demo_lab.py        # then open http://127.0.0.1:8767/
```

For real collection there are two ways to run an instance. Use the first on
your own Windows machine; the second anywhere else.

## A. On this machine (Windows, no Docker)

```powershell
cd umbra
.\run-local.ps1          # Tor + API/GUI + crawl worker; prints the URL
.\stop-local.ps1         # stops worker + API (Tor stays up unless -IncludeTor)
```

If PowerShell refuses to run the script ("running scripts is disabled on this
system"), your execution policy is `Restricted`. Either run it as
`powershell -ExecutionPolicy Bypass -File .\run-local.ps1`, or once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

Everything lives in `%LOCALAPPDATA%\umbra\` — the database, `serve.log`,
`worker.log`, and PID files. Re-running `run-local.ps1` is safe; it leaves
anything already running alone. Nothing is stored in a temp directory.

## B. Anywhere else (Docker)

```bash
cd umbra
docker compose up -d --build
docker compose logs api | grep -A3 "bootstrap admin key"   # the API never runs open on a network bind
```

Then follow `deploy/README.md`. **This path has not yet been exercised end to
end** — the first `docker compose up` is itself a test, and whatever it turns
up is the most valuable bug report there is.

## A 15-minute walkthrough

Open http://localhost:8000/ and go through the tabs in this order. Each step
names what you should see; if you don't, that's a finding.

1. **Overview.** A coloured collection-health banner sits above the counts:
   `Collecting` (green), `Idle`, `Stalled` (amber) or `Failing` (red). The
   counts can't tell you collection has stopped — the banner can. Refreshes
   every 5 s.

2. **Crawl → source pack.** Pick `getting-started`, click *Queue this pack*.
   It lists official onion services of public organisations (a news site, a
   search engine, privacy-software projects), each verified over Tor before
   it shipped — safe targets for a first crawl. Pack entries are pinned, so
   the crawl stays on those hosts. Then either wait for the worker's next
   pass, or press *Start crawl* with the seed box empty. Your own packs go in
   the directory named by `UMBRA_SOURCE_PACKS_PATH`.

3. **Crawl → your own target.** Paste one or more `.onion` URLs you care
   about, tick **Stay on these sites**, set depth 3, *Start crawl*. Live
   progress appears below. Leave the box unticked for a directory or wiki,
   where the outbound links are the point.

4. **Sites.** Every host seen, with pages fetched vs queued. Click a host to
   load it into the Crawl tab. *Re-prioritise queue* re-ranks links already
   waiting after a scorer or pin change.

5. **Timeline.** *Notable only* shows outages, recoveries and new actor
   identifiers; *Service status* shows who is up and who went dark, and when.
   A service disappearing is the exit-scam / seizure signal. Events are
   transitions only, so an empty filter means nothing moved.

6. **Indicators → ★ Actor identifiers.** Wallets, PGP fingerprints, published
   contact addresses — the things that identify *who is selling*, and the
   exact set the actor graph links on. Unfiltered views drown in onion links.

7. **Actors.** Clusters of reused identifiers. Click one to see the
   identifiers and the pages they span.

8. **Watchlists → change / event.** Add *a service goes offline*, optionally
   scoped to one host, with a webhook URL you control. Alerts fire after each
   pass and POST the full event. The URL must be a public host — anything on
   a private or loopback address is refused, deliberately.

9. **Indicators → exports.** *STIX 2.1* for MISP / OpenCTI (deterministic ids,
   so re-imports update rather than duplicate). *Evidence bundle* for a
   report — read its README first: it says exactly what it does and does not
   establish, and needs `UMBRA_STORE_HTML=true` for the capture hash to be
   verifiable.

10. **Stop and restart.** `.\stop-local.ps1` then `.\run-local.ps1`. The
    frontier is in the database, so the crawl resumes where it left off, and
    the run health view marks the interrupted pass as *interrupted*, not
    failed.

## What to report back

Anything the walkthrough said you'd see and you didn't. Anything that took
more than one attempt. Anything you had to ask about. The GUI's *? What is
this* button is the built-in explanation — if it didn't answer the question,
that's a finding too.

## Before testing with real targets

Talk to counsel. The compliance gate controls what is *stored* (no media,
operator blocklist, known-bad hash drop, hashed credentials only); it does not
make collection lawful in your jurisdiction. Law-enforcement users have a
lawful basis for collection that a private company must construct — but
retention and handling of what's collected still need signing off.
