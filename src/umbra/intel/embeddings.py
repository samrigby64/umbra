"""Embeddings and semantic search.

An :class:`Embedder` turns page text into a fixed-length unit vector; search
embeds a query and ranks stored vectors by cosine similarity.

The default :class:`HashingEmbedder` is a dependency-free, offline hashing
vectoriser — it needs no API key and runs anywhere, so semantic search works out
of the box. It captures lexical overlap, not deep semantics; swap in a real
model (Voyage, a local sentence-transformer, …) behind the same interface for
production-grade "find pages about X" quality. Storage is brute-force cosine over
float32 blobs, which is fine to ~10^5 pages; on Postgres, move to pgvector.
"""

from __future__ import annotations

import contextlib
import asyncio
import heapq
import threading
import os
import re
import zlib
from typing import Protocol

import numpy as np
import sqlalchemy as sa

from ..config import Settings
from ..db import Database
from ..logging import get_logger
from ..models import Embedding, Page, Ioc

log = get_logger("embeddings")

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


@contextlib.contextmanager
def _env(**overrides: str):
    """Temporarily set environment variables, restoring the previous values."""
    previous = {k: os.environ.get(k) for k in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, text: str) -> np.ndarray:
        ...


class HashingEmbedder:
    """Bag-of-words hashed into ``dim`` buckets, L2-normalised. Deterministic
    and offline. Cosine similarity then approximates shared-vocabulary overlap.
    """

    def __init__(self, dim: int = 256) -> None:
        self.name = f"hashing-{dim}"
        self.dim = dim

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        for token in _TOKEN_RE.findall((text or "").lower()):
            # crc32 is a STABLE hash. Python's built-in hash() is randomised per
            # process (PYTHONHASHSEED), which would make embeddings written by
            # `umbra crawl` unmatchable by a later `umbra search` process.
            bucket = zlib.crc32(token.encode("utf-8")) % self.dim
            vec[bucket] += 1.0
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec


class LocalEmbedder:
    """A real, offline semantic embedder backed by fastembed (ONNX — no torch).

    This is the architecture-fit upgrade over :class:`HashingEmbedder`: it drops
    into the same synchronous ``embed()`` (CPU-bound, no per-call API cost), so
    both search *and* the focused-crawl scorer become genuinely semantic. The
    model downloads once on first use. Optional dependency: ``pip install
    umbra-intel[embeddings]``.

    (An API embedder such as Voyage would give higher quality but needs an
    async/batch pipeline to avoid per-link/per-page blocking calls — that's the
    next step, not this one.)
    """

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        self._lock = threading.Lock()
        from fastembed import TextEmbedding  # optional dep, imported lazily

        try:
            self._model = TextEmbedding(model_name=model_name)
        except Exception:
            # A stale or revoked HuggingFace token in ~/.cache/huggingface/token
            # is sent automatically and makes the hub reject the request, even
            # though these model weights are public and need no auth at all.
            # Retry once ignoring it rather than degrading to hashing search,
            # which is a far worse outcome than an unauthenticated download.
            log.warning("model load failed; retrying without the stored HF token")
            with _env(HF_HUB_DISABLE_IMPLICIT_TOKEN="1", HF_TOKEN=""):
                self._model = TextEmbedding(model_name=model_name)
        self.name = f"local:{model_name}"
        self.dim = len(self._embed_raw("probe"))

    def _embed_raw(self, text: str) -> np.ndarray:
        with self._lock:
            return np.asarray(next(iter(self._model.embed([text or " "]))), dtype=np.float32)

    def embed(self, text: str) -> np.ndarray:
        vec = self._embed_raw(text)
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec


def build_embedder(settings: Settings) -> Embedder:
    kind = settings.embedder_kind
    if kind == "hashing":
        return HashingEmbedder(dim=settings.embedding_dim)
    if kind == "local":
        try:
            return LocalEmbedder(settings.local_embedding_model)
        except Exception as exc:  # missing dep or model download failure
            log.warning("local embedder unavailable (%s); falling back to hashing", exc)
            return HashingEmbedder(dim=settings.embedding_dim)
    raise ValueError(
        f"unknown embedder_kind {kind!r} (use 'hashing' or 'local')"
    )


def to_bytes(vec: np.ndarray) -> bytes:
    return np.asarray(vec, dtype=np.float32).tobytes()


async def search(db: Database, embedder: Embedder, query: str, top_k: int = 10) -> list[dict]:
    """Exact cosine ranking with bounded vector memory and matching model identity."""
    if top_k < 1 or not query.strip():
        return []
    qv = await asyncio.to_thread(embedder.embed, query)
    best: list[tuple[float, str]] = []
    cursor = ""
    async with db.session() as session:
        while True:
            rows = (await session.execute(sa.select(
                Embedding.page_url, Embedding.vector
            ).join(Page, Page.url == Embedding.page_url).where(
                Embedding.model == embedder.name, Embedding.dim == embedder.dim,
                Embedding.page_url > cursor, Page.blocked.is_(False),
                Page.content.isnot(None),
            ).order_by(Embedding.page_url).limit(512))).all()
            if not rows:
                break
            cursor = rows[-1][0]
            for url, blob in rows:
                if len(blob) != embedder.dim * 4:
                    continue
                score = float(np.frombuffer(blob, dtype=np.float32) @ qv)
                if not np.isfinite(score):
                    continue
                item = (score, url)
                if len(best) < top_k:
                    heapq.heappush(best, item)
                elif item > best[0]:
                    heapq.heapreplace(best, item)
            await asyncio.sleep(0)
        top = sorted(best, reverse=True)
        top_urls = [url for _, url in top]

        pages = {
            p.url: p
            for p in (
                await session.execute(sa.select(Page.url, Page.title, Page.summary).where(
                    Page.url.in_(top_urls)
                ))
            ).all()
        }

    results = []
    for score, url in top:
        page = pages.get(url)
        results.append(
            {
                "url": url,
                "score": score,
                "title": page.title if page else None,
                "summary": page.summary if page else None,
            }
        )
    return results


async def exact_search(db: Database, value: str, top_k: int = 20) -> list[dict]:
    """Exact identifier equality: never approximate wallet/key matches."""
    async with db.session() as session:
        rows = (await session.execute(sa.select(Page).join(
            Ioc, Ioc.page_url == Page.url
        ).where(Ioc.value == value.strip(), Page.blocked.is_(False)).distinct()
            .order_by(Page.url).limit(top_k))).scalars().all()
    return [{"url": p.url, "title": p.title, "summary": p.summary,
             "score": 1.0, "match": "exact identifier"} for p in rows]
