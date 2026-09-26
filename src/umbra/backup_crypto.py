"""Streaming AES-256-GCM envelope for SQLite backups.

The header is authenticated. Decrypted bytes stay in a temporary file until
the GCM tag verifies; callers must not activate an unverified file.
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"UMBRA-BACKUP-1\x00"


def key_path(settings):
    path = Path(settings.backup_key_file) if settings.backup_key_file else (
        Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local/share"))) /
        "umbra" / "backup.key")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    if path.stat().st_size != 32:
        raise ValueError("Backup key must contain exactly 32 bytes")
    return path


def encrypt(source, target, key_file):
    key = Path(key_file).read_bytes()
    nonce = os.urandom(12)
    header = MAGIC + nonce
    cipher = Cipher(algorithms.AES256(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    with Path(source).open("rb") as inp, Path(target).open("xb") as out:
        out.write(header)
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            out.write(cipher.update(chunk))
        out.write(cipher.finalize())
        out.write(cipher.tag)


def decrypt(source, target, key_file):
    key = Path(key_file).read_bytes()
    with Path(source).open("rb") as inp:
        header = inp.read(len(MAGIC)+12)
        if not header.startswith(MAGIC) or len(header) != len(MAGIC)+12:
            raise ValueError("Invalid encrypted backup header")
        size = Path(source).stat().st_size-len(header)-16
        if size < 0:
            raise ValueError("Truncated encrypted backup")
        inp.seek(-16, 2)
        tag = inp.read(16)
        inp.seek(len(header))
        cipher = Cipher(algorithms.AES256(key), modes.GCM(header[-12:], tag)).decryptor()
        cipher.authenticate_additional_data(header)
        with Path(target).open("xb") as out:
            while size:
                chunk = inp.read(min(size, 1024*1024))
                if not chunk:
                    raise ValueError("Truncated backup")
                out.write(cipher.update(chunk))
                size -= len(chunk)
            out.write(cipher.finalize())
