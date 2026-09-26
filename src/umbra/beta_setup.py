"""Private local account/MFA setup: python -m umbra.beta_setup USERNAME."""
import argparse
import asyncio
import getpass
import os
from pathlib import Path

import pyotp
import sqlalchemy as sa

from .access import audit, password_hash
from .config import Settings
from .db import Database
from .models import UserAccount
from .security import secret_cipher


async def enrol(settings, username, password, secret, code):
    from .security import verify_totp
    db = Database(settings.database_url)
    try:
        await db.create_all()
        async with db.write_session() as s:
            if await s.scalar(sa.select(sa.func.count()).select_from(UserAccount)):
                raise ValueError('Accounts already exist. Use the existing administrator and MFA setup.')
            user = UserAccount(username=username, password_hash=password_hash(password),
                               role='admin', active=True,
                               totp_secret=secret_cipher(settings).encrypt(secret.encode()).decode())
            verify_totp(user, code, settings)
            s.add(user)
            await audit(s, 'local-beta-setup', 'admin_mfa_enrolled', {'username': username})
            await s.commit()
    finally:
        await db.dispose()


def enable_beta(path):
    original = path.read_text(encoding='utf-8') if path.exists() else ''
    lines = [line for line in original.splitlines() if not line.strip().startswith('UMBRA_BETA_MODE=')]
    lines.append('UMBRA_BETA_MODE=true')
    temporary = path.with_name(path.name+'.beta-setup.tmp')
    with temporary.open('x', encoding='utf-8') as f:
        f.write('\n'.join(lines)+'\n')
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('username')
    parser.add_argument('--env-file', type=Path, default=Path('.env'))
    parser.add_argument('--contact-file', type=Path, default=Path('beta-support-contact.txt'))
    args = parser.parse_args()
    if not args.username.strip() or len(args.username) > 100:
        parser.error('Use a nonempty username of at most 100 characters')
    settings = Settings(_env_file=args.env_file)
    contact = input('Monitored private support email or channel for this pilot: ').strip()
    if not contact or len(contact) > 500:
        parser.error('Provide an actual monitored contact of at most 500 characters')
    if args.contact_file.exists():
        parser.error('Support contact file already exists; review it before rerunning setup')
    password = getpass.getpass('Administrator password (12–256 characters): ')
    if not 12 <= len(password) <= 256 or password != getpass.getpass('Confirm password: '):
        parser.error('Passwords must match and have 12–256 characters')
    secret = pyotp.random_base32()
    print('Privately add this manual setup key to your authenticator under Umbra:')
    print(secret)
    print('Do not paste the key into chat, logs or support tickets.')
    code = getpass.getpass('Code from your authenticator: ')
    asyncio.run(enrol(settings, args.username.strip().lower(), password, secret, code))
    with args.contact_file.open('x', encoding='utf-8') as f:
        f.write(contact+'\n')
    enable_beta(args.env_file)
    print('Administrator and MFA created; beta mode saved. Restart Umbra, then sign in with a fresh code.')


if __name__ == '__main__':
    main()
