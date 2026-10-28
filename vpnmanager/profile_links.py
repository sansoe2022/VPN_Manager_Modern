"""Expiring bearer links for OpenVPN client profiles, never server private keys."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit

ROOT = Path('/var/lib/vpnmanager/profile-links')
ROUTE = re.compile(r'^/profiles/([A-Za-z0-9_-]{43})/client\.ovpn$')


def base_url(m, config):
    custom = config.get('download_base_url', '').rstrip('/')
    if custom:
        parsed = urlsplit(custom)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment):
            raise ValueError('Use an HTTP/HTTPS download base URL without credentials, query or fragment.')
        m.endpoint(parsed.hostname)
        if parsed.port is not None:
            m.port(parsed.port)
        return custom
    host = m.endpoint(config['endpoint'])
    if ':' in host:
        host = '[' + host + ']'
    return f'http://{host}:{m.port(config["online_port"])}'


def create(m, config, minutes=60):
    if not isinstance(minutes, int) or not 1 <= minutes <= 1440:
        raise ValueError('Link validity must be 1-1440 minutes.')
    base = base_url(m, config)
    cleanup()
    token = secrets.token_urlsafe(32)
    identity = hashlib.sha256(token.encode()).hexdigest()
    directory = ROOT / identity
    directory.mkdir(parents=True, mode=0o700)
    ROOT.chmod(0o700)
    profile = directory / 'client.ovpn'
    try:
        m.export_client(config, profile)
        if b'PRIVATE KEY' in profile.read_bytes():
            raise ValueError('A client download must not contain a server/CA private key.')
        expires = int(time.time()) + minutes * 60
        m.write(directory / 'record.json', json.dumps({'expires_at': expires}) + '\n')
    except BaseException:
        profile.unlink(missing_ok=True)
        (directory / 'record.json').unlink(missing_ok=True)
        directory.rmdir()
        raise
    return base + '/profiles/' + token + '/client.ovpn', expires


def read(path, now=None):
    match = ROUTE.fullmatch(path)
    if not match:
        return None
    identity = hashlib.sha256(match[1].encode()).hexdigest()
    directory = ROOT / identity
    profile, record = directory / 'client.ovpn', directory / 'record.json'
    if directory.is_symlink() or profile.is_symlink() or record.is_symlink():
        return None
    try:
        expires = json.loads(record.read_text())['expires_at']
        if expires <= (time.time() if now is None else now) or profile.stat().st_size > 1024 * 1024:
            return None
        body = profile.read_bytes()
        if b'PRIVATE KEY' in body:
            return None
        return body
    except (OSError, ValueError, KeyError, TypeError):
        return None


def cleanup(force=False, now=None):
    now = time.time() if now is None else now
    removed = 0
    if not ROOT.exists():
        return removed
    for directory in ROOT.iterdir():
        if not re.fullmatch(r'[a-f0-9]{64}', directory.name) or directory.is_symlink() or not directory.is_dir():
            continue
        try:
            expires = json.loads((directory / 'record.json').read_text())['expires_at']
            if not force and expires > now:
                continue
            (directory / 'client.ovpn').unlink(missing_ok=True)
            (directory / 'record.json').unlink(missing_ok=True)
            directory.rmdir()
            removed += 1
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return removed
