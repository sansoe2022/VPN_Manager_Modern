"""Private account metadata shared by the menu, expiry timer and bots."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import time

PATH = Path('/var/lib/vpnmanager/accounts.json')


def load():
    return json.loads(PATH.read_text()) if PATH.exists() else {}


@contextmanager
def transaction():
    PATH.parent.mkdir(parents=True, exist_ok=True)
    with PATH.with_suffix('.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = load()
        yield data
        temp = PATH.with_suffix('.new')
        temp.write_text(json.dumps(data, indent=2) + '\n')
        temp.chmod(0o600)
        os.replace(temp, PATH)


def update(username, **fields):
    with transaction() as data:
        data.setdefault(username, {'limit': 1, 'created': int(time.time())}).update(fields)


def remove(username):
    with transaction() as data:
        data.pop(username, None)


def expired(record, shadow, now=None):
    now = time.time() if now is None else now
    expiry = record.get('expires_at')
    day = shadow[7]
    return ((expiry is not None and expiry <= now)
            or (bool(day) and int(day) <= int(now // 86400)))


def verify_password(username, password):
    """Check an existing managed user's hash using the distro libcrypt ABI."""
    import ctypes
    import ctypes.util
    import hmac
    import subprocess
    if not password or len(password) > 512:
        return False
    result = subprocess.run(['getent', 'shadow', username], capture_output=True, text=True)
    if result.returncode:
        return False
    stored = result.stdout.split(':')[1].lstrip('!')
    if not stored or stored.startswith('*'):
        return False
    library = ctypes.util.find_library('crypt')
    if not library:
        raise ValueError('The system password verification library is missing.')
    crypt = ctypes.CDLL(library).crypt
    crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    crypt.restype = ctypes.c_char_p
    # crypt() uses shared storage on some distro versions.
    with _crypt_lock:
        actual = crypt(password.encode(), stored.encode())
        return bool(actual and hmac.compare_digest(actual, stored.encode()))


import threading
_crypt_lock = threading.Lock()
