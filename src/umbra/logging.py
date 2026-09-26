"""Minimal, dependency-free structured-ish logging.

Kept deliberately small. Swap for structlog / JSON logs when you add the
product surface (layer 5) and want machine-parseable logs.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> logging.Logger:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root = logging.getLogger("umbra")
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    root.propagate = False
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"umbra.{name}")
