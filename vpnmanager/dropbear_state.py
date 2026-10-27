"""Track authenticated Dropbear connections, including root-owned -N sessions."""
import json
from pathlib import Path
import os

PATH = Path('/var/lib/vpnmanager/dropbear-sessions.json')


def identity(pid):
    process = Path('/proc', str(pid))
    if process.joinpath('comm').read_text().strip() != 'dropbear':
        raise ValueError('The process is not Dropbear.')
    # Field 22 is starttime. Splitting after the closing ')' handles comm spaces.
    return process.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]


def save(data):
    PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = PATH.with_suffix('.new')
    temp.write_text(json.dumps(data))
    temp.chmod(0o600)
    os.replace(temp, PATH)


def sessions():
    if not PATH.exists():
        return []
    result = []
    for pid, record in json.loads(PATH.read_text()).items():
        try:
            if identity(int(pid)) == record['start']:
                result.append((record['user'], int(pid)))
        except (OSError, ValueError):
            continue
    return result
