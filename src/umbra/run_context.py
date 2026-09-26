"""Task-local run attribution, inherited by async crawl workers."""
from contextvars import ContextVar

current_run: ContextVar[int | None] = ContextVar("umbra_current_run", default=None)
