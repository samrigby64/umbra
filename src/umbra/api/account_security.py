"""Individual-account MFA and administrator-issued password recovery."""
import asyncio
import datetime as dt
import hashlib
import secrets
import time
from collections import deque

import pyotp
import sqlalchemy as sa
from fastapi import Header, HTTPException
from pydantic import BaseModel, Field

from ..access import audit, check_password, password_hash, principal
from ..models import LoginSession, RecoveryToken, UserAccount, utcnow
from ..security import secret_cipher, verify_totp


class Proof(BaseModel):
    password: str = Field(min_length=12, max_length=256)
    otp: str = Field(default="", max_length=6)


class Code(BaseModel):
    otp: str = Field(min_length=6, max_length=6)


class Reset(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    password: str = Field(min_length=12, max_length=256)
    otp: str = Field(default="", max_length=6)


def register(app, db, settings, auth, admin):
    attempts = deque(maxlen=30)
    def throttle():
        now = time.monotonic()
        while attempts and attempts[0] < now-60:
            attempts.popleft()
        if len(attempts) >= 20:
            raise HTTPException(429, "Too many security attempts; retry in a minute")
        attempts.append(now)

    async def identity(token):
        who = await principal(db, token)
        if not who["user_id"]:
            raise HTTPException(400, "Sign in with an individual account")
        return who

    async def proof(who, password):
        async with db.session() as s:
            user = await s.get(UserAccount, who["user_id"])
            stored = user.password_hash
        if not await asyncio.to_thread(check_password, password, stored):
            raise HTTPException(401, "Invalid credentials")
        return stored

    @app.get("/auth/security", dependencies=auth)
    async def status(x_api_key: str | None = Header(None)):
        who = await identity(x_api_key)
        async with db.session() as s:
            user = await s.get(UserAccount, who["user_id"])
            return {"mfa_enabled": bool(user.totp_secret)}

    @app.post("/auth/mfa/setup", dependencies=auth)
    async def setup(payload: Proof, x_api_key: str | None = Header(None)):
        throttle()
        who = await identity(x_api_key)
        stored = await proof(who, payload.password)
        async with db.write_session() as s:
            user = await s.get(UserAccount, who["user_id"])
            if user.password_hash != stored or not user.active:
                raise HTTPException(401, "Account changed")
            if user.totp_secret:
                raise HTTPException(409, "Authenticator already enabled")
            secret = pyotp.random_base32()
            user.totp_pending = secret_cipher(settings).encrypt(secret.encode()).decode()
            await audit(s, who, "mfa_setup_started", {})
            await s.commit()
            return {"secret": secret, "uri": pyotp.TOTP(secret).provisioning_uri(
                name=user.username, issuer_name="Umbra")}

    @app.post("/auth/mfa/confirm", dependencies=auth)
    async def confirm(payload: Code, x_api_key: str | None = Header(None)):
        throttle()
        who = await identity(x_api_key)
        async with db.write_session() as s:
            user = await s.get(UserAccount, who["user_id"])
            verify_totp(user, payload.otp, settings, pending=True)
            user.totp_secret, user.totp_pending = user.totp_pending, None
            await s.execute(sa.delete(LoginSession).where(LoginSession.user_id == user.id))
            await audit(s, who, "mfa_enabled", {})
            await s.commit()
        return {"enabled": True, "signed_out": True}

    @app.post("/auth/mfa/disable", dependencies=auth)
    async def disable(payload: Proof, x_api_key: str | None = Header(None)):
        throttle()
        who = await identity(x_api_key)
        stored = await proof(who, payload.password)
        async with db.write_session() as s:
            user = await s.get(UserAccount, who["user_id"])
            if user.password_hash != stored:
                raise HTTPException(401, "Account changed")
            verify_totp(user, payload.otp, settings)
            user.totp_secret = user.totp_pending = user.totp_last_step = None
            await s.execute(sa.delete(LoginSession).where(LoginSession.user_id == user.id))
            await audit(s, who, "mfa_disabled", {})
            await s.commit()
        return {"enabled": False, "signed_out": True}

    @app.post("/team/{user_id}/recovery", dependencies=admin)
    async def recovery(user_id: int, x_api_key: str | None = Header(None)):
        who = await principal(db, x_api_key)
        token = secrets.token_urlsafe(32)
        async with db.write_session() as s:
            user = await s.get(UserAccount, user_id)
            if not user or not user.active:
                raise HTTPException(404, "Active account not found")
            await s.execute(sa.delete(RecoveryToken).where(RecoveryToken.user_id == user_id))
            s.add(RecoveryToken(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                                user_id=user_id, expires_at=utcnow()+dt.timedelta(minutes=15)))
            await audit(s, who, "password_recovery_issued", {"user_id": user_id})
            await s.commit()
        return {"token": token, "expires_in": 900,
                "notice": "Deliver privately to the account owner. MFA remains required."}

    @app.post("/auth/recover")
    async def recover(payload: Reset):
        throttle()
        digest = hashlib.sha256(payload.token.encode()).hexdigest()
        async with db.session() as s:
            if not await s.scalar(sa.select(RecoveryToken.token_hash).where(
                RecoveryToken.token_hash == digest, RecoveryToken.expires_at > utcnow()
            )):
                raise HTTPException(401, "Invalid or expired recovery token")
        hashed = await asyncio.to_thread(password_hash, payload.password)
        async with db.write_session() as s:
            token = await s.get(RecoveryToken, digest)
            if not token or token.expires_at.replace(tzinfo=dt.timezone.utc) <= utcnow():
                raise HTTPException(401, "Invalid or expired recovery token")
            user = await s.get(UserAccount, token.user_id)
            if not user or not user.active:
                raise HTTPException(401, "Account unavailable")
            if user.totp_secret:
                verify_totp(user, payload.otp, settings)
            user.password_hash = hashed
            await s.delete(token)
            await s.execute(sa.delete(LoginSession).where(LoginSession.user_id == user.id))
            await audit(s, f"user:{user.id}:{user.username}", "password_recovered", {})
            await s.commit()
        return {"recovered": True, "signed_out": True}
