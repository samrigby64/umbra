import httpx
import pytest

from umbra.api import create_app
from umbra.config import Settings
from umbra.db import Database
from umbra.models import ApiKey
from umbra.access import password_hash
from umbra.models import UserAccount


@pytest.mark.asyncio
async def test_beta_refuses_anonymous_and_shared_keys(tmp_path):
    settings = Settings(_env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path/'beta.db'}",
                        beta_mode=True, embedder_kind="hashing", backup_interval_hours=0)
    db = Database(settings.database_url)
    await db.create_all()
    async with db.write_session() as s:
        s.add(ApiKey(key="legacy-shared-key", name="old", role="admin"))
        s.add(UserAccount(username="tester", password_hash=password_hash("synthetic-test-password"),
                          role="viewer", active=True))
        await s.commit()
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                base_url="http://test") as client:
        assert (await client.get("/stats")).status_code == 401
        assert (await client.get("/stats", headers={"X-API-Key": "legacy-shared-key"})).status_code == 401
        response = await client.get("/")
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert (await client.post("/collection/jobs", headers={"Origin": "https://hostile.example"},
                                  json={})).status_code == 403
        login = await client.post("/auth/login", json={"username": "tester", "password": "synthetic-test-password"})
        assert login.status_code == 200
        token = login.json()["token"]
        assert (await client.get("/stats", headers={"X-API-Key": token})).status_code == 200
        assert (await client.post("/collection/jobs", headers={"X-API-Key": token}, json={
            "name": "denied", "seeds": ["https://fixture.example/"]})).status_code == 403
    await db.dispose()
