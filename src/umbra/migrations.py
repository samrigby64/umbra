"""Versioned adoption of the legacy additive schema.

Revision 004 adopts 0.1–0.3 databases without discarding rows. The schema
fingerprint prevents silently shipping changed models under the same revision.
Future revisions must be added explicitly to REVISIONS.
"""
import hashlib
import json

import sqlalchemy as sa

from .models import Base

REVISION = "004"
REVISIONS = {"004": "collection jobs, capture provenance, extraction feedback, MFA/recovery"}


def fingerprint():
    schema = [(t.name, [(c.name, str(c.type), c.nullable) for c in t.columns])
              for t in Base.metadata.sorted_tables]
    return hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()


async def check_revision(conn):
    await conn.execute(sa.text(
        "CREATE TABLE IF NOT EXISTS schema_migrations (revision VARCHAR(16) PRIMARY KEY, "
        "description TEXT NOT NULL, fingerprint VARCHAR(64) NOT NULL, applied_at VARCHAR(64) NOT NULL)"))
    rows = (await conn.execute(sa.text("SELECT revision, fingerprint FROM schema_migrations"))).all()
    for revision, digest in rows:
        if revision not in REVISIONS:
            raise RuntimeError("Database is from an unsupported newer schema; refusing downgrade")
        if revision == REVISION and digest != fingerprint():
            raise RuntimeError("Model schema changed without a new migration revision")


async def stamp_revision(conn):
    from .models import utcnow
    if not await conn.scalar(sa.text("SELECT revision FROM schema_migrations WHERE revision=:r"),
                             {"r": REVISION}):
        await conn.execute(sa.text(
            "INSERT INTO schema_migrations (revision,description,fingerprint,applied_at) "
            "VALUES (:r,:d,:f,:at)"),
            {"r": REVISION, "d": REVISIONS[REVISION], "f": fingerprint(),
             "at": utcnow().isoformat()})
