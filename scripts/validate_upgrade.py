"""Back up configured SQLite, restore to a NEW temporary file, verify upgrade."""
import asyncio
import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from umbra.backup_crypto import key_path
from umbra.config import Settings
from umbra.db import Database
from umbra.maintenance import backup, database_path, restore


async def main():
    settings = Settings()
    source = database_path(settings.database_url)
    tables = ("pages", "page_versions", "iocs", "users", "investigations")
    def counts(path):
        with closing(sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)) as conn:
            return {t: conn.execute("SELECT count(*) FROM "+t).fetchone()[0] for t in tables}
    before = counts(source)
    manifest = backup(settings.database_url, key_file=key_path(settings))
    directory = Path(tempfile.mkdtemp(prefix="umbra-040-restore-"))
    target = directory/"restored.db"
    result = restore(source.parent/"backups"/manifest["file"], target,
                     key_file=key_path(settings))
    db = Database("sqlite+aiosqlite:///"+target.as_posix())
    try:
        await db.create_all()
        after = counts(target)
        if before != after:
            raise RuntimeError("Restored migration changed protected row counts")
    finally:
        await db.dispose()
    report = {"backup": manifest, "restore": result, "rows_before": before,
              "rows_after": after, "counts_preserved": before == after,
              "key_location": str(key_path(settings)), "database_modified": False}
    Path("reports").mkdir(exist_ok=True)
    Path("reports/release-040-upgrade.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"counts_preserved": True, "counts": after,
                      "encrypted_backup": manifest["file"], "restored_to": str(target)}))


if __name__ == "__main__":
    asyncio.run(main())
