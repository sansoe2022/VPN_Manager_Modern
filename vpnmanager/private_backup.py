"""Private managed-account backups; never replace the host passwd/shadow files."""
import io
import json
import os
from pathlib import Path
import pwd
import tarfile
import time

import accounts


def create(m):
    path = m.STATE / 'backups' / ('sshplus-' + str(time.time_ns()) + '.tar.gz')
    users = []
    for username in m.users():
        fields = m.capture('getent', 'shadow', username).split(':')
        users.append({'name': username, 'hash': fields[1], 'expiry': fields[7],
                      'metadata': accounts.load().get(username, {})})
    payload = json.dumps({'format': 1, 'accounts': users}).encode()
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as output, tarfile.open(fileobj=output, mode='w:gz', dereference=True) as archive:
        member = tarfile.TarInfo('manifest.json')
        member.size = len(payload)
        member.mode = 0o600
        archive.addfile(member, io.BytesIO(payload))
        archive.add('/etc/vpnmanager', arcname='config')
        for item in Path('/etc/openvpn/server').glob('vpnmanager*'):
            archive.add(item, arcname='openvpn/' + item.name)
    path.chmod(0o600)
    return path


def validate_members(archive):
    members = archive.getmembers()
    total = 0
    for item in members:
        path = Path(item.name)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise ValueError('Unsafe path in backup.')
        if not (item.isfile() or item.isdir()):
            raise ValueError('Backup links/devices are not accepted.')
        if path.parts[0] not in ('manifest.json', 'config', 'openvpn'):
            raise ValueError('Unknown backup section.')
        if path.parts[0] == 'openvpn' and (len(path.parts) != 2 or not path.name.startswith('vpnmanager')):
            raise ValueError('Unknown OpenVPN backup path.')
        total += item.size
        if total > 64 * 1024 * 1024:
            raise ValueError('Backup is too large.')
    return members


def restore(m, filename):
    try:
        source = tarfile.open(filename, 'r:gz')
    except (tarfile.TarError, OSError) as error:
        raise ValueError('Cannot open this file as a private SSHPlus backup.') from error
    with source as archive:
        members = validate_members(archive)
        try:
            manifest = json.load(archive.extractfile('manifest.json'))
        except (KeyError, TypeError) as error:
            raise ValueError('The backup manifest is missing or invalid.') from error
        if not isinstance(manifest, dict) or not isinstance(manifest.get('accounts'), list):
            raise ValueError('Invalid account manifest.')
        if manifest.get('format') != 1:
            raise ValueError('Unsupported backup format.')
        # Validate all accounts before modifying any existing account or config.
        current = set(m.users())
        for user in manifest['accounts']:
            if not isinstance(user, dict) or not {'name', 'hash', 'expiry', 'metadata'} <= user.keys():
                raise ValueError('Invalid account record.')
            if not isinstance(user['hash'], str) or not isinstance(user['metadata'], dict):
                raise ValueError('Invalid account password/metadata.')
            record = user['metadata']
            if not isinstance(record.get('limit', 1), int) or not 1 <= record.get('limit', 1) <= 1000:
                raise ValueError('Invalid connection limit in backup.')
            if record.get('expires_at') is not None and not isinstance(record['expires_at'], (int, float)):
                raise ValueError('Invalid trial expiry in backup.')
            m.valid_user(user['name'])
            if user['name'] == 'root' or any(char in user['hash'] for char in ':\r\n'):
                raise ValueError('Invalid account in backup.')
            if user['expiry'] and not str(user['expiry']).isdigit():
                raise ValueError('Invalid expiry in backup.')
            try:
                pwd.getpwnam(user['name'])
            except KeyError:
                continue
            if user['name'] not in current:
                raise ValueError('Backup conflicts with an unmanaged account: ' + user['name'])
        before = create(m)
        print('Before-restore backup: ' + str(before))
        for user in manifest['accounts']:
            name = user['name']
            if name not in current:
                m.run('useradd', '-M', '-g', m.GROUP, '-s', '/usr/sbin/nologin', name)
            m.run('chpasswd', '-e', input=name + ':' + user['hash'] + '\n')
            m.run('chage', '-E', str(user['expiry'] or '-1'), name)
            accounts.update(name, **user['metadata'])
        for item in members:
            if not item.isfile() or item.name == 'manifest.json':
                continue
            parts = Path(item.name).parts
            base = Path('/etc/vpnmanager') if parts[0] == 'config' else Path('/etc/openvpn/server')
            target = base.joinpath(*parts[1:])
            # Refuse pre-existing symlinks in any destination component.
            if any(parent.is_symlink() for parent in (target, *target.parents)):
                raise ValueError('A restore destination is a symbolic link.')
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.extractfile(item).read()
            temp = target.with_name(target.name + '.restore')
            temp.write_bytes(content)
            temp.chmod(0o600)
            temp.replace(target)
    print('Restore complete. Run the installer to regenerate units, then restart from menu 26.')
