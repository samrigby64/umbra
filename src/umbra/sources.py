"""Source packs — curated seed lists, so coverage is configuration not code.

The crawler is only as valuable as what you point it at. Measured on a real
corpus seeded from a directory wiki, **76.5% of crawled pages carried no
commercial signal at all** — no wallet, no key, no contact, no listing. The
engine was fine; the sources were privacy-tech documentation and hobbyist blogs.

A pack is a named, versioned list of seeds with provenance. Different customers
need different coverage — a fraud team and an incident-response team barely
overlap — and the point of packing them is that this is a data change rather than
a fork of the product.

**On provenance.** Every source carries where it came from and when it was last
seen alive, because a seed list is a claim about the world that decays. A pack
shipped with plausible-looking but unverified addresses is worse than no pack:
it burns crawl budget on dead hosts and quietly teaches the operator that the
tool does not work. Packs generated from a real crawl record the observation that
justified including each host.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from .logging import get_logger

log = get_logger("sources")

BUNDLED_DIR = Path(__file__).parent / "sourcepacks"


@dataclasses.dataclass
class Source:
    url: str
    note: str = ""
    last_seen: str | None = None      # ISO date this host last answered
    evidence: str | None = None       # why it is in the pack (e.g. "38 listings")


@dataclasses.dataclass
class SourcePack:
    name: str
    description: str
    category: str
    version: str
    sources: list[Source]
    origin: str = "bundled"

    @property
    def urls(self) -> list[str]:
        return [s.url for s in self.sources]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "version": self.version,
            "origin": self.origin,
            "count": len(self.sources),
            "sources": [dataclasses.asdict(s) for s in self.sources],
        }


def _read(path: Path, origin: str) -> SourcePack | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return SourcePack(
            name=raw.get("name") or path.stem,
            description=raw.get("description", ""),
            category=raw.get("category", "other"),
            version=raw.get("version", "unknown"),
            origin=origin,
            sources=[
                Source(
                    url=s["url"],
                    note=s.get("note", ""),
                    last_seen=s.get("last_seen"),
                    evidence=s.get("evidence"),
                )
                for s in raw.get("sources", [])
                if s.get("url")
            ],
        )
    except Exception:
        log.exception("could not read source pack %s", path)
        return None


def available(extra_dir: str | Path | None = None) -> list[SourcePack]:
    """Bundled packs, plus any in the operator's own directory.

    Operator packs win on name collision: a customer curating their own list for
    a sector should not have it silently overridden by a shipped default.
    """
    packs: dict[str, SourcePack] = {}
    for directory, origin in ((BUNDLED_DIR, "bundled"), (extra_dir, "operator")):
        if not directory:
            continue
        path = Path(directory)
        if not path.is_dir():
            continue
        for file in sorted(path.glob("*.json")):
            pack = _read(file, origin)
            if pack:
                packs[pack.name] = pack
    return sorted(packs.values(), key=lambda p: (p.category, p.name))


def get(name: str, extra_dir: str | Path | None = None) -> SourcePack | None:
    for pack in available(extra_dir):
        if pack.name == name:
            return pack
    return None


async def seed_pack(db, settings, name: str, force: bool = False) -> dict:
    """Queue every source in ``name`` onto the crawl frontier."""
    from .crawl.scheduler import Scheduler

    pack = get(name, settings.source_packs_path)
    if pack is None:
        raise KeyError(name)

    scheduler = Scheduler(db, settings)
    await scheduler.load()
    # Pack entries are targets by definition — the pack exists because these
    # hosts carried signal — so the crawl stays on them.
    queued = await scheduler.seed(pack.urls, force=force, pin=True)
    log.info("seeded pack %r: %d of %d source(s) queued", name, queued, len(pack.urls))
    return {"pack": name, "sources": len(pack.urls), "queued": queued}
