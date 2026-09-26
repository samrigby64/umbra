"""Backwards-compatibility shim.

The in-memory frontier was replaced by the resumable, DB-backed
:class:`umbra.crawl.scheduler.Scheduler`. ``CrawlItem`` now lives there; this
re-export keeps older imports working.
"""

from .scheduler import CrawlItem, Scheduler

__all__ = ["CrawlItem", "Scheduler"]
