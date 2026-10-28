"""Full manager migration; never replace the host passwd/shadow or admin SSH config."""
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time

import accounts
import backup_crypto
import downloads
import proxy_config
import progress

ROOTS = {'config': Path('/etc/vpnmanager'), 'openvpn': Path('/etc/openvpn/server'),
         'source': Path('/usr/local/lib/vpnmanager'), 'units': Path('/etc/systemd/system'),
         'squid': Path('/etc/squid'), 'sysctl': Path('/etc/sysctl.d'),
         'xui': Path('/usr/local/x-ui'), 'xui-config': Path('/etc/x-ui'),
         'dropbear': Path('/etc/dropbear'),
         'commands': Path('/usr/local/bin'), 'xui-command': Path('/usr/bin')}
LIMIT = 1024 * 1024 * 1024


def allowed(name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        return False
    if name == 'manifest.json':
        return True
    root, *rest = path.parts
    if root not in ROOTS:
        return False
    if not rest:
        return True
    if root == 'openvpn':
        return len(rest) == 1 and rest[0].startswith('vpnmanager')
    if root == 'units':
        return len(rest) == 1 and (rest[0].startswith('vpnmanager-') or rest[0] == 'x-ui.service')
    if root == 'squid':
        return rest == ['squid.conf']
    if root == 'sysctl':
        return rest in (['90-vpnmanager.conf'], ['91-vpnmanager-bbr.conf'])
    if root == 'commands':
        return rest == ['badvpn-udpgw']
    if root == 'dropbear':
        return len(rest) == 1 and re.fullmatch(r'dropbear_(rsa|ecdsa|ed25519)_host_key', rest[0]) is not None
    if root == 'xui-command':
        return rest == ['x-ui']
    return True


def managed_ssh_keys(m):
    config = ROOTS['config'] / 'sshd_config'
    if not config.exists() or 'HostKey ' in config.read_text():
        return
    lines = []
    for kind in ('ed25519', 'rsa', 'ecdsa'):
        old = Path('/etc/ssh') / ('ssh_host_' + kind + '_key')
        if old.exists():
            new = ROOTS['config'] / old.name
            if not new.exists():
                m.write(new, old.read_text())
            lines.append('HostKey ' + str(new))
    if lines:
        m.write(config, config.read_text() + '\n' + '\n'.join(lines) + '\n')


def create(m):
    directory = m.STATE / 'backups'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / ('vpnmanager-' + str(time.time_ns()) + '.tar.gz')
    managed_ssh_keys(m)
    users = []
    for username in m.users():
        fields = m.capture('getent', 'shadow', username).split(':')
        users.append({'name': username, 'hash': fields[1], 'expiry': fields[7], 'metadata': accounts.load().get(username, {})})
    units = [path.name for path in ROOTS['units'].glob('vpnmanager-*') if path.is_file()]
    if (ROOTS['units'] / 'x-ui.service').exists():
        units.append('x-ui.service')
    unit_states = {}
    for unit in units:
        status = subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, text=True)
        unit_states[unit] = status.stdout.strip() in ('enabled', 'enabled-runtime')
    swap = m.STATE / 'swapfile'
    manifest = {'format': 2, 'arch': platform.machine(), 'accounts': users, 'unit_states': unit_states,
                'swap_gib': round(swap.stat().st_size / 1024**3) if swap.exists() else 0}
    payload = json.dumps(manifest).encode()
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output, tarfile.open(fileobj=output, mode='w:gz', dereference=False) as archive:
            member = tarfile.TarInfo('manifest.json')
            member.size, member.mode = len(payload), 0o600
            archive.addfile(member, io.BytesIO(payload))
            total = 0
            for section, root in ROOTS.items():
                if not root.exists():
                    continue
                for item in sorted(root.rglob('*')) if section in ('config', 'source', 'xui', 'xui-config') else sorted(root.iterdir()):
                    relative = item.relative_to(root)
                    name = str(Path(section) / relative)
                    if '__pycache__' in relative.parts or not allowed(name) or item.is_symlink() or not item.is_file():
                        continue
                    total += item.stat().st_size
                    if total > LIMIT:
                        raise ValueError('Managed backup exceeds 1 GiB; inspect large files under managed paths.')
                    if section == 'xui-config' and item.suffix == '.db':
                        with tempfile.TemporaryDirectory(prefix='vpnmanager-sqlite-') as temp:
                            snapshot = Path(temp) / 'snapshot.db'
                            with sqlite3.connect('file:' + str(item) + '?mode=ro', uri=True) as original, sqlite3.connect(snapshot) as copy:
                                original.backup(copy)
                            archive.add(snapshot, arcname=name, recursive=False)
                    elif section == 'xui-config' and item.name.endswith(('-wal', '-shm')):
                        continue
                    else:
                        archive.add(item, arcname=name, recursive=False)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def validate_members(archive):
    members, seen, total = archive.getmembers(), set(), 0
    for item in members:
        if not allowed(item.name) or item.name in seen or not (item.isfile() or item.isdir()):
            raise ValueError('Unsafe, duplicate or unknown backup member.')
        if item.isfile() and item.name != 'manifest.json' and len(Path(item.name).parts) < 2:
            raise ValueError('Backup section roots must be directories.')
        seen.add(item.name)
        total += item.size
        if item.size < 0 or total > LIMIT:
            raise ValueError('Backup is too large.')
    return members


@progress.operation('Validating and applying backup')
def restore(m, filename, activate=True, endpoint=None):
    try:
        source = tarfile.open(filename, 'r:gz')
    except (tarfile.TarError, OSError) as error:
        raise ValueError('Cannot open this file as a VPN Manager backup.') from error
    with source as archive:
        members = validate_members(archive)
        try:
            manifest = json.load(archive.extractfile('manifest.json'))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('The backup manifest is missing or invalid.') from error
        if not isinstance(manifest, dict) or not isinstance(manifest.get('accounts'), list) or manifest.get('format') not in (1, 2):
            raise ValueError('Unsupported backup manifest.')
        if manifest.get('arch', platform.machine()) != platform.machine():
            raise ValueError('This full backup contains binaries for a different CPU architecture. Use a VPS with the same architecture.')
        if not isinstance(manifest.get('unit_states', {}), dict) or any(
                not re.fullmatch(r'(?:vpnmanager-[a-z0-9_-]+\.(?:service|timer)|x-ui\.service)', unit)
                or not isinstance(value, bool) for unit, value in manifest.get('unit_states', {}).items()):
            raise ValueError('Invalid service states in backup.')
        if not isinstance(manifest.get('swap_gib', 0), int) or not 0 <= manifest.get('swap_gib', 0) <= 32:
            raise ValueError('Invalid managed swap size in backup.')
        try:
            incoming = json.load(archive.extractfile('config/config.json'))
            restored_services = incoming.get('enabled', [])
            if not isinstance(restored_services, list) or any(not isinstance(name, str) or name not in m.SERVICES for name in restored_services):
                raise ValueError('Unknown service configuration in backup.')
            proxy_config.listeners(incoming, configured=True)
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            raise ValueError('Missing or invalid manager configuration in backup.') from error
        current = set(m.users())
        names = set()
        for user in manifest['accounts']:
            if not isinstance(user, dict) or not {'name', 'hash', 'expiry', 'metadata'} <= user.keys():
                raise ValueError('Invalid account record.')
            if not isinstance(user['hash'], str) or not isinstance(user['metadata'], dict):
                raise ValueError('Invalid account password/metadata.')
            m.valid_user(user['name'])
            if user['name'] in names or user['name'] == 'root' or any(char in user['hash'] for char in ':\r\n'):
                raise ValueError('Invalid or duplicate account in backup.')
            names.add(user['name'])
            record = user['metadata']
            if not isinstance(record.get('limit', 1), int) or not 1 <= record.get('limit', 1) <= 1000:
                raise ValueError('Invalid connection limit in backup.')
            if record.get('expires_at') is not None and not isinstance(record['expires_at'], (int, float)):
                raise ValueError('Invalid trial expiry in backup.')
            if 'password' in record:
                m.validate_password(record['password'])
            if user['expiry'] and not str(user['expiry']).isdigit():
                raise ValueError('Invalid expiry in backup.')
            try:
                pwd.getpwnam(user['name'])
            except KeyError:
                continue
            if user['name'] not in current:
                raise ValueError('Backup conflicts with an unmanaged account: ' + user['name'])
        # Validate every destination before modifying accounts or writing files.
        for item in members:
            if item.name == 'manifest.json':
                continue
            parts = Path(item.name).parts
            target = ROOTS[parts[0]].joinpath(*parts[1:])
            if any(parent.is_symlink() for parent in (target, *target.parents)):
                raise ValueError('A restore destination is a symbolic link.')
        with progress.stage('Saving current state before restore'):
            before = create(m)
        print('Before-restore backup: ' + str(before), flush=True)
        # Stop only manager-owned services before replacing managed binaries/databases.
        if activate:
            owned = {m.SERVICES[name] for name in m.load()['enabled'] if name in m.SERVICES}
            owned.update(m.SERVICES[name] for name in restored_services)
            if (ROOTS['config'] / 'sshd_config').exists():
                owned.add('vpnmanager-sshd')
            for unit in owned:
                subprocess.run(['systemctl', 'stop', unit], capture_output=True, text=True)
        print(f'Restoring {len(manifest["accounts"])} account(s)...', flush=True)
        for user in manifest['accounts']:
            name = user['name']
            if name not in current:
                m.run('useradd', '-M', '-g', m.GROUP, '-s', '/usr/sbin/nologin', name)
            m.run('chpasswd', '-e', input=name + ':' + user['hash'] + '\n')
            m.run('chage', '-E', str(user['expiry'] or '-1'), name)
            accounts.update(name, **user['metadata'])
        print('Restoring script, keys and service files...', flush=True)
        for item in members:
            if not item.isfile() or item.name == 'manifest.json':
                continue
            parts = Path(item.name).parts
            target = ROOTS[parts[0]].joinpath(*parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            temp = target.with_name(target.name + '.restore')
            with archive.extractfile(item) as input_file, temp.open('wb') as output:
                temp.chmod(0o600)
                shutil.copyfileobj(input_file, output, 1024 * 1024)
            mode = (0o755 if item.mode & 0o111 else 0o644) if parts[0] in ('source', 'commands', 'xui-command') else 0o644 if parts[0] in ('units', 'sysctl', 'squid') else 0o700 if item.mode & 0o111 else 0o600
            temp.chmod(mode)
            temp.replace(target)
        if endpoint:
            config = m.load()
            config['endpoint'] = m.endpoint(endpoint)
            if config.get('udp_port'):
                config['udp_server_name'] = config['endpoint']
            m.save(config)
    if activate:
        rebuild(m, manifest)
    print('Full manager restore complete.' if activate else 'Files/accounts restored; service activation was skipped for this check.')


def rebuild(m, manifest=None):
    import extras
    import udp_runtime
    manifest = manifest or {}
    config = m.load()
    enabled = set(config['enabled'])
    unknown = enabled - set(m.SERVICES)
    if unknown:
        raise ValueError('Unknown service names in backup configuration.')
    print('[1/4] Regenerating manager units and launchers...', flush=True)
    m.initialize()
    m.write('/usr/local/bin/vpnmanager', '#!/usr/bin/env bash\nexec python3 -B /usr/local/lib/vpnmanager/manager.py "$@"\n', 0o755)
    for alias in ('menu', 'vpnmenu'):
        path = Path('/usr/local/bin') / alias
        path.unlink(missing_ok=True)
        path.symlink_to('/usr/local/bin/vpnmanager')
    print('[2/4] Restoring configured protocol services...', flush=True)
    if (ROOTS['config'] / 'sshd_config').exists():
        m.configure_ssh(config, config['ssh_port'], config.get('ssh_bind', '127.0.0.1'))
    for name in ('openvpn', 'dropbear', 'tunnel', 'tls', 'sslh', 'squid', 'online', 'badvpn', 'udp', 'xui'):
        if name not in enabled:
            continue
        print('Restoring ' + name + '...', flush=True)
        if name in ('dropbear', 'sslh', 'badvpn'):
            getattr(extras, name)(m, config, config[name + '_port'])
        elif name == 'udp':
            udp_runtime.configure(m, config, config['udp_port'])
        elif name == 'xui':
            m.run('systemctl', 'enable', '--now', 'x-ui')
        else:
            m.configure(name, config, config[name + '_port'])
    print('[3/4] Restoring timers, bots and managed firewall settings...', flush=True)
    if config.get('limiter_enabled') or manifest.get('unit_states', {}).get('vpnmanager-limiter.timer'):
        extras.limiter(m, True)
    if manifest.get('unit_states', {}).get('vpnmanager-torrent.service'):
        extras.torrent(m, True)
    for role in ('admin', 'trial', 'reseller'):
        unit = f'vpnmanager-bot-{role}.service'
        if (ROOTS['config'] / f'bot-{role}.json').exists() and manifest.get('unit_states', {}).get(unit):
            m.run('systemctl', 'enable', '--now', unit)
    bbr = ROOTS['sysctl'] / '91-vpnmanager-bbr.conf'
    if bbr.exists():
        m.run('sysctl', '-p', str(bbr))
    if manifest.get('swap_gib'):
        extras.swap(m, int(manifest['swap_gib']))
    for unit, enabled_at_boot in manifest.get('unit_states', {}).items():
        if not enabled_at_boot and (unit.startswith('vpnmanager-') or unit == 'x-ui.service'):
            m.run('systemctl', 'disable', unit)
    print('[4/4] Services restored. Update DNS and provider firewall rules for this VPS.', flush=True)


def restore_source(m, source, password=None, activate=True, endpoint=None):
    with tempfile.TemporaryDirectory(prefix='vpnmanager-restore-') as directory:
        root = Path(directory)
        remote = source.startswith(('https://', 'http://'))
        with progress.stage('Downloading backup' if remote else 'Opening local backup'):
            path = downloads.fetch(source, root / 'download', LIMIT, progress=progress.transfer) if remote else Path(source)
        with path.open('rb') as file:
            encrypted = file.read(len(backup_crypto.MAGIC)) == backup_crypto.MAGIC
        if remote and not encrypted:
            raise ValueError('URL restore requires an encrypted VPN Manager backup.')
        if encrypted:
            if password is None:
                import getpass
                password = getpass.getpass('Backup password: ')
            with progress.stage('Verifying backup password and decrypting'):
                path = backup_crypto.decrypt(path, root / 'archive.tar.gz', password)
        restore(m, path, activate=activate, endpoint=endpoint)
