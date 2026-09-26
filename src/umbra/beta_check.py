"""Read-only invitation checks: python -m umbra.beta_check --soak-directory PATH."""
import argparse
import asyncio
import json
import shutil
import time
from pathlib import Path

import sqlalchemy as sa

from .config import Settings
from .db import Database
from .maintenance import database_path
from .models import UserAccount


async def assess(settings, soak_directory, contact_file):
    checks = {}
    checks['individual_sessions_required'] = settings.beta_mode
    db = Database(settings.database_url)
    try:
        async with db.session() as s:
            users = (await s.scalars(sa.select(UserAccount).where(UserAccount.active.is_(True)))).all()
            checks['administrator_enrolled'] = any(u.role == 'admin' and u.totp_secret for u in users)
            checks['all_active_accounts_have_mfa'] = bool(users) and all(u.totp_secret for u in users)
    finally:
        await db.dispose()
    contact = contact_file.read_text(encoding='utf-8').strip() if contact_file.exists() else ''
    checks['support_contact_recorded'] = bool(contact)
    checks['automatic_page_purge_disabled'] = settings.retention_days == 0
    path = database_path(settings.database_url)
    size = sum(p.stat().st_size for p in (path, Path(str(path)+'-wal'), Path(str(path)+'-shm')) if p.exists())
    free = shutil.disk_usage(path.parent).free
    checks['storage_below_review_threshold'] = size < 1_000_000_000 and free >= 2_000_000_000
    status_file = soak_directory/'status.json'
    status = json.loads(status_file.read_text()) if status_file.exists() else {}
    checks['synthetic_48_hours_recorded'] = (status.get('status') == 'completed' and
        status.get('covered_hours', 0) >= 48 and status.get('processing_errors', 1) == 0)
    # A human assessment must still review gaps, Tor samples and growth. Runtime
    # completion alone must never turn this CLI into a release certification.
    return {'checks': checks, 'failed_checks': [k for k,v in checks.items() if not v],
            'storage_bytes': size, 'free_bytes': free,
            'synthetic_covered_hours': status.get('covered_hours', 0),
            'synthetic_sample_age_s': time.time()-status['sampled_at'] if status.get('sampled_at') else None,
            'release_approved': False,
            'notice': 'Operational checks only. Review Tor coverage, live extraction limitations, retention and named operator sign-off before inviting testers.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--soak-directory', type=Path, required=True)
    parser.add_argument('--contact-file', type=Path, default=Path('beta-support-contact.txt'))
    args = parser.parse_args()
    report = asyncio.run(assess(Settings(), args.soak_directory, args.contact_file))
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if report['failed_checks'] else 0)


if __name__ == '__main__':
    main()
