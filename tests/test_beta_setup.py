import json

import pyotp
import pytest
import sqlalchemy as sa
from fastapi import HTTPException

from umbra.beta_setup import enrol, enable_beta
from umbra.beta_check import assess
from umbra.config import Settings
from umbra.db import Database
from umbra.models import UserAccount


async def test_setup_requires_valid_mfa_and_preserves_existing_configuration(tmp_path):
    settings = Settings(_env_file=None, database_url=f'sqlite+aiosqlite:///{tmp_path/"lab.db"}',
                        security_key_file=str(tmp_path/'security.key'))
    secret = pyotp.random_base32()
    with pytest.raises(HTTPException):
        await enrol(settings, 'administrator', 'fictional-password', secret, 'invalid')
    db = Database(settings.database_url)
    async with db.session() as s:
        assert await s.scalar(sa.select(sa.func.count()).select_from(UserAccount)) == 0
    await enrol(settings, 'administrator', 'fictional-password', secret, pyotp.TOTP(secret).now())
    with pytest.raises(ValueError, match='Accounts already exist'):
        await enrol(settings, 'another', 'fictional-password', secret, pyotp.TOTP(secret).now())
    env = tmp_path/'.env'
    env.write_text('UMBRA_LLM_ENABLED=false\nUMBRA_BETA_MODE=false\n')
    enable_beta(env)
    assert env.read_text() == 'UMBRA_LLM_ENABLED=false\nUMBRA_BETA_MODE=true\n'
    await db.dispose()


async def test_readiness_never_approves_short_or_failed_endurance(tmp_path):
    settings = Settings(_env_file=None, database_url=f'sqlite+aiosqlite:///{tmp_path/"lab.db"}')
    db = Database(settings.database_url)
    await db.create_all()
    (tmp_path/'status.json').write_text(json.dumps({'status':'running','covered_hours':16,
                                                  'processing_errors':0}))
    result = await assess(settings, tmp_path, tmp_path/'contact.txt')
    assert not result['release_approved']
    assert not result['checks']['synthetic_48_hours_recorded']
    assert not result['checks']['administrator_enrolled']
    assert not result['checks']['support_contact_recorded']
    await db.dispose()
