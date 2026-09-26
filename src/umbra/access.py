"""Individual sessions, case ACLs and a transactional, hash-linked audit log."""

import datetime as dt
import hashlib
import hmac
import json
import secrets

import sqlalchemy as sa
from fastapi import HTTPException

from .models import ApiKey, AuditEntry, CaseMember, LoginSession, UserAccount, utcnow


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"{salt}${digest.hex()}"


def check_password(password, stored):
    return hmac.compare_digest(password_hash(password, stored.split("$")[0]), stored)


async def principal(db, token):
    async with db.session() as s:
        if token:
            key = await s.scalar(
                sa.select(ApiKey).where(ApiKey.key == token, ApiKey.active.is_(True))
            )
            if key and not getattr(db, "require_individual_accounts", False):
                return {"actor": f"key:{key.id}:{key.name}", "role": key.role, "user_id": None}
            digest = hashlib.sha256(token.encode()).hexdigest()
            user = await s.scalar(
                sa.select(UserAccount)
                .join(LoginSession, LoginSession.user_id == UserAccount.id)
                .where(
                    LoginSession.token_hash == digest,
                    LoginSession.expires_at > utcnow(),
                    UserAccount.active.is_(True),
                )
            )
            if user:
                return {
                    "actor": f"user:{user.id}:{user.username}",
                    "role": user.role,
                    "user_id": user.id,
                }
            raise HTTPException(401, "Invalid or expired credentials")
        keys = await s.scalar(
            sa.select(sa.func.count()).select_from(ApiKey).where(ApiKey.active.is_(True))
        )
        # Once individual accounts exist, disabling them must never reopen the server.
        users = await s.scalar(sa.select(sa.func.count()).select_from(UserAccount))
        if keys or users or getattr(db, "require_individual_accounts", False):
            raise HTTPException(401, "Sign in or supply X-API-Key")
        return {"actor": "local-open", "role": "open", "user_id": None}


async def case_access(s, case_id, who, write=False):
    if who["role"] in ("admin", "open"):
        return
    member = await s.get(CaseMember, (case_id, who["user_id"])) if who["user_id"] else None
    if not member or (write and (member.permission != "write" or who["role"] == "viewer")):
        raise HTTPException(403, "Case access denied")


def audit_digest(previous, actor, action, detail, at):
    return hashlib.sha256(
        json.dumps(
            [previous, actor, action, detail, at], ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


async def audit(s, who, action, detail):
    """Call inside write_session: the domain change and its audit commit together."""
    previous = (
        await s.scalar(sa.select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1))
        or "0" * 64
    )
    at = utcnow().isoformat()
    detail = json.dumps(detail, sort_keys=True, default=str)
    actor = who["actor"] if isinstance(who, dict) else who
    row = AuditEntry(
        actor=actor,
        action=action,
        detail=detail,
        at=at,
        previous_hash=previous,
        entry_hash=audit_digest(previous, actor, action, detail, at),
    )
    s.add(row)
    await s.flush()


async def new_session(s, user):
    token = secrets.token_urlsafe(32)
    s.add(
        LoginSession(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            user_id=user.id,
            expires_at=utcnow() + dt.timedelta(hours=8),
        )
    )
    return token
