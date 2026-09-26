"""API-key lifecycle. The bootstrap banner tells an operator to replace the
minted key; that is only honest advice if revocation exists and cannot lock them
out by accident."""

import pytest
import sqlalchemy as sa
import typer

from umbra.cli import _run_apikey, _run_apikey_revoke
from umbra.config import Settings
from umbra.db import Database
from umbra.models import ApiKey


async def _active(url: str) -> dict[str, str]:
    db = Database(url)
    async with db.session() as s:
        rows = (await s.execute(sa.select(ApiKey).where(ApiKey.active.is_(True)))).scalars().all()
    await db.dispose()
    return {k.name: k.role for k in rows}


async def test_revoke_deactivates_a_key(tmp_path):
    settings = Settings()
    settings.database_url = f"sqlite+aiosqlite:///{tmp_path / 'k.db'}"
    await _run_apikey(settings, "bootstrap-admin", "admin")
    await _run_apikey(settings, "ops", "admin")
    await _run_apikey(settings, "dashboard", "viewer")

    await _run_apikey_revoke(settings, "bootstrap-admin")
    assert await _active(settings.database_url) == {"ops": "admin", "dashboard": "viewer"}

    # revoking an already-revoked or unknown name is an error, not a silent no-op
    with pytest.raises(typer.BadParameter):
        await _run_apikey_revoke(settings, "bootstrap-admin")


async def test_cannot_revoke_the_last_admin_key(tmp_path):
    """Losing the last admin key leaves the service open (loopback) or minting a
    new bootstrap key (public) — either way, an operator locked out of their own
    keys by one command. Make them create the replacement first."""
    settings = Settings()
    settings.database_url = f"sqlite+aiosqlite:///{tmp_path / 'last.db'}"
    await _run_apikey(settings, "only-admin", "admin")
    await _run_apikey(settings, "viewer", "viewer")

    with pytest.raises(typer.BadParameter, match="last active admin"):
        await _run_apikey_revoke(settings, "only-admin")
    assert "only-admin" in await _active(settings.database_url)

    await _run_apikey_revoke(settings, "viewer")  # a viewer can always go
    assert await _active(settings.database_url) == {"only-admin": "admin"}
