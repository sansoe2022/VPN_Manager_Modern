"""Expiring bearer links for encrypted full backups only."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
import backup_crypto
import profile_links

ROOT = Path('/var/lib/vpnmanager/backup-links')
ROUTE = re.compile(r'^/backups/([A-Za-z0-9_-]{43})/backup\.vpnbak$')


def create(m, config, archive, password, minutes=60):
    if not isinstance(minutes, int) or not 1 <= minutes <= 1440:
        raise ValueError('Choose a validity from 1 to 1440 minutes.')
    base = profile_links.base_url(m, config)
    token = secrets.token_urlsafe(32)
    directory = ROOT / hashlib.sha256(token.encode()).hexdigest()
    directory.mkdir(parents=True, mode=0o700)
    ROOT.chmod(0o700)
    try:
        backup_crypto.encrypt(archive, directory / 'backup.vpnbak', password)
        if (directory / 'backup.vpnbak').stat().st_size > backup_crypto.LIMIT:
            raise ValueError('Encrypted backup exceeds the 1 GiB download limit.')
        expiry = int(time.time()) + minutes * 60
        m.write(directory / 'record.json', json.dumps({'expires_at': expiry}))
    except BaseException:
        for name in ('backup.vpnbak', 'record.json'):
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()
        raise
    return base + '/backups/' + token + '/backup.vpnbak', expiry


def resolve(path, now=None):
    match = ROUTE.fullmatch(path)
    if not match:
        return None
    directory = ROOT / hashlib.sha256(match[1].encode()).hexdigest()
    source, record = directory / 'backup.vpnbak', directory / 'record.json'
    if any(item.is_symlink() for item in (directory, source, record)):
        return None
    try:
        if json.loads(record.read_text())['expires_at'] <= (time.time() if now is None else now):
            return None
        if source.stat().st_size > backup_crypto.LIMIT:
            return None
        with source.open('rb') as file:
            if file.read(len(backup_crypto.MAGIC)) != backup_crypto.MAGIC:
                return None
        return source
    except (OSError, ValueError, KeyError, TypeError):
        return None


def cleanup(now=None):
    if not ROOT.exists():
        return
    now = time.time() if now is None else now
    for directory in ROOT.iterdir():
        if directory.is_symlink() or not re.fullmatch('[a-f0-9]{64}', directory.name):
            continue
        try:
            if json.loads((directory / 'record.json').read_text())['expires_at'] > now:
                continue
            (directory / 'backup.vpnbak').unlink(missing_ok=True)
            (directory / 'record.json').unlink(missing_ok=True)
            directory.rmdir()
        except (OSError, ValueError, KeyError, TypeError):
            continue
