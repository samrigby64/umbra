"""Local SQLite backup/restore and diagnostics; never overwrite a restore target."""

import argparse
import datetime as dt
import hashlib
import json
import sqlite3
from pathlib import Path
from contextlib import closing

from sqlalchemy.engine import make_url


def database_path(url):
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite" or parsed.database in (None, ":memory:"):
        raise ValueError(
            "This backup tool supports file-backed SQLite; use native PostgreSQL backups for PostgreSQL"
        )
    return Path(parsed.database).resolve()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup(url, directory=None, *, key_file=None):
    source = database_path(url)
    if not source.exists():
        raise ValueError("Database does not exist")
    directory = Path(directory) if directory else source.parent / "backups"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (
        "umbra-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f") + ".db"
    )
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(target)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Backup failed integrity check")
    if key_file:
        from .backup_crypto import encrypt
        encrypted = target.with_suffix(".ubak")
        try:
            encrypt(target, encrypted, key_file)
        except Exception:
            encrypted.unlink(missing_ok=True)
            raise
        finally:
            target.unlink(missing_ok=True)
        target = encrypted
    digest = file_hash(target)
    manifest = {
        "file": target.name,
        "sha256": digest,
        "bytes": target.stat().st_size,
        "integrity": "ok",
        "encrypted": bool(key_file),
        "encryption": "AES-256-GCM" if key_file else None,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    target.with_suffix(".json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def restore(source, target, *, key_file=None):
    source, target = Path(source).resolve(), Path(target).resolve()
    metadata = json.loads(source.with_suffix(".json").read_text(encoding="utf-8"))
    if file_hash(source) != metadata["sha256"]:
        raise ValueError("Backup checksum mismatch")
    if target.exists():
        raise ValueError(
            "Restore target already exists; restore to a new file and test before switching"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    if metadata.get("encrypted"):
        if not key_file:
            raise ValueError("Encrypted backup requires --key-file")
        import tempfile
        from .backup_crypto import decrypt
        from cryptography.exceptions import InvalidTag
        with tempfile.TemporaryDirectory(dir=target.parent) as folder:
            verified = Path(folder) / "verified.db"
            try:
                decrypt(source, verified, key_file)
            except InvalidTag:
                raise ValueError("Backup authentication failed; wrong key or tampered data") from None
            with closing(sqlite3.connect(verified)) as conn:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Decrypted database failed integrity check")
            import shutil
            with verified.open("rb") as inp, target.open("xb") as out:
                shutil.copyfileobj(inp, out, length=1024*1024)
        return {"restored_to": str(target), "integrity": "ok", "authenticated": True}
    # Exclusive creation prevents a concurrent operator from losing a file.
    import shutil

    with source.open("rb") as inp, target.open("xb") as out:
        shutil.copyfileobj(inp, out, length=1024 * 1024)
    if file_hash(target) != metadata["sha256"]:
        raise ValueError("Copied backup checksum mismatch; target was not activated")
    with closing(sqlite3.connect(target)) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Restored database failed integrity check")
    return {"restored_to": str(target), "integrity": "ok"}


def main():
    from .config import Settings

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--key-file")
    r = sub.add_parser("restore")
    r.add_argument("source")
    r.add_argument("target")
    r.add_argument("--key-file")
    args = parser.parse_args()
    result = (
        backup(Settings().database_url, key_file=args.key_file)
        if args.command == "backup"
        else restore(args.source, args.target, key_file=args.key_file)
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
