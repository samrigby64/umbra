"""Enrichment pipeline — the seam for *threat-intel analysis* (#3).

An enricher turns a parsed page into structured records (IOCs today; page-type
classification, NER, embeddings, etc. later). Each returns a list of
:class:`~umbra.models.Ioc` rows the crawler persists. The interface is async so a
future enricher can call out to a model/API without blocking the event loop.
"""

from __future__ import annotations

from typing import Protocol

from ..crawl.parse import ParsedPage
from ..models import Ioc, Page


class Enricher(Protocol):
    name: str

    async def enrich(self, page: Page, parsed: ParsedPage) -> list[Ioc]:
        ...
