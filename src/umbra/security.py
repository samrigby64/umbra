"""TOTP secret protection and single-use verification."""
import os
import time
from pathlib import Path

import pyotp
from cryptography.fernet import Fernet
from fastapi import HTTPException


def secret_cipher(settings):
    path = Path(settings.security_key_file) if settings.security_key_file else (
        Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local/share"))) /
        "umbra" / "security.key")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    return Fernet(path.read_bytes().strip())


def verify_totp(user, code, settings, *, pending=False, now=None):
    encrypted = user.totp_pending if pending else user.totp_secret
    if not encrypted:
        raise HTTPException(400, "No authenticator configured")
    secret = secret_cipher(settings).decrypt(encrypted.encode()).decode()
    step = int((time.time() if now is None else now) // 30)
    otp = pyotp.TOTP(secret)
    for candidate in (step, step-1, step+1):
        if candidate > (user.totp_last_step if user.totp_last_step is not None else -1):
            if otp.verify(code or "", for_time=candidate*30):
                user.totp_last_step = candidate
                return
    raise HTTPException(401, "Invalid or already used authenticator code")
