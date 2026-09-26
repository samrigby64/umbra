"""Operator .env files must not change deterministic test scope or enable services."""

import pytest
from umbra.config import Settings


@pytest.fixture(autouse=True)
def isolated_default_config(monkeypatch):
    monkeypatch.setitem(Settings.model_config, "env_file", None)
