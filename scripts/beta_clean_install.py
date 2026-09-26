"""Run from the installed wheel on another machine; synthetic data only."""
import asyncio
import json
import tempfile
from pathlib import Path

import httpx

from umbra.api import create_app
from umbra.config import Settings
from umbra.db import Database
from umbra.maintenance import backup, restore
from umbra.backup_crypto import key_path
from umbra import __version__


async def main():
    directory = Path(tempfile.mkdtemp(prefix="umbra-clean-check-", dir=Path(__file__).resolve().parent))
    settings = Settings(_env_file=None, database_url="sqlite+aiosqlite:///"+str(directory/"clean.db"),
                        embedder_kind="hashing", use_tor=False, beta_mode=True,
                        preview_mode=True, backup_interval_hours=0,
                        backup_key_file=str(directory/"test-backup.key"))
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/health")).json()["version"] == __version__
            assert (await c.get("/stats")).status_code == 401
            page = await c.get("/")
            assert page.status_code == 200
            assert "Your first investigation" in (await c.get("/workflow.js")).text
    manifest = backup(settings.database_url, key_file=key_path(settings))
    restored = directory/"restored.db"
    restore(directory/"backups"/manifest["file"], restored, key_file=key_path(settings))
    db = Database("sqlite+aiosqlite:///"+str(restored))
    await db.create_all()
    await db.dispose()
    print(json.dumps({"version": __version__, "clean_install": True, "anonymous_denied": True,
                      "gui_assets": True, "encrypted_restore": True,
                      "scope": "Linux installed wheel, synthetic empty database; no live Tor collection"}))


if __name__ == "__main__":
    asyncio.run(main())
