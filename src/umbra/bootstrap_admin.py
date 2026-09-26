"""Interactive local bootstrap: python -m umbra.bootstrap_admin USERNAME."""
import argparse
import asyncio
import getpass

import sqlalchemy as sa

from .access import audit, password_hash
from .config import Settings
from .db import Database
from .models import UserAccount


async def create(username, password):
    db = Database(Settings().database_url)
    try:
        await db.create_all()
        async with db.write_session() as s:
            if await s.scalar(sa.select(sa.func.count()).select_from(UserAccount)):
                raise ValueError("Accounts already exist; use Team management or recovery.")
            s.add(UserAccount(username=username, password_hash=password_hash(password),
                              role="admin", active=True))
            await audit(s, "local-bootstrap", "admin_created", {"username": username})
            await s.commit()
    finally:
        await db.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    args = parser.parse_args()
    if not args.username.strip() or len(args.username) > 100:
        parser.error("Use a nonempty username of at most 100 characters")
    password = getpass.getpass("New administrator password (12+ characters): ")
    if len(password) < 12 or password != getpass.getpass("Confirm password: "):
        parser.error("Passwords must match and have at least 12 characters")
    asyncio.run(create(args.username.strip().lower(), password))
    print("Administrator created. Sign in and enrol an authenticator before inviting testers.")


if __name__ == "__main__":
    main()
