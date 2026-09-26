"""Defaults a customer hits on day one, before they have read any docs."""

from pathlib import Path

from umbra.config import Settings
from umbra.db import Database


def test_default_database_is_absolute_and_per_user(monkeypatch):
    """A working-directory-relative default means two commands run from two
    directories use two databases, and a temp-directory demo loses everything
    to routine cleanup. Both happened."""
    monkeypatch.delenv("UMBRA_DATABASE_URL", raising=False)
    url = Settings().database_url

    assert url.startswith("sqlite+aiosqlite:///")
    path = url.removeprefix("sqlite+aiosqlite:///")
    assert Path(path).is_absolute()
    assert path.endswith("umbra/umbra.db")
    assert "Temp" not in path and "tmp" not in path.lower()


async def test_sqlite_directory_is_created_on_first_use(tmp_path):
    """Fresh install, data directory does not exist yet: the first command must
    not die with 'unable to open database file'."""
    target = tmp_path / "does" / "not" / "exist" / "umbra.db"
    db = Database(f"sqlite+aiosqlite:///{target.as_posix()}")
    await db.create_all()
    assert target.exists()
    await db.dispose()
