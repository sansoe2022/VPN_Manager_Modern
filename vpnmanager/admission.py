"""Atomic per-account admission shared by SSH, OpenVPN, Dropbear and Hysteria."""
import contextlib
import fcntl
import grp
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import time
from socketserver import ThreadingUnixStreamServer, StreamRequestHandler

import accounts
import dropbear_state
import online
import udp_runtime

ROOT = Path('/run/vpnmanager')
SOCKET = '/run/vpnmanager-admission/gate.sock'
PAM_SKIP = 'account [success=1 default=ignore] pam_succeed_if.so quiet user notingroup vpnmanager'
PAM_LINE = 'account requisite pam_exec.so quiet /usr/bin/python3 /usr/local/lib/vpnmanager/admission.py pam'
HOOK = '/usr/bin/python3 /usr/local/lib/vpnmanager/openvpn_gate.py'


def process(pid):
    try:
        stat = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        return None if stat[0] == 'Z' else (int(stat[1]), stat[19])
    except (OSError, ValueError, IndexError):
        return None


def ssh_owner(pid):
    # OpenSSH may fork a temporary PAM helper inheriting the sshd process title.
    # Select its outer privileged connection process, never the server listener.
    owner = None
    for _ in range(12):
        info = process(pid)
        if not info:
            break
        directory = Path('/proc', str(pid))
        name = directory.joinpath('comm').read_text().strip()
        title = directory.joinpath('cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        if name in ('sshd', 'sshd-session') and '[priv]' in title:
            owner = pid
        pid = info[0]
    return owner


def observed(m):
    result = {}
    # The authenticated child and the PAM account hook share the privileged parent.
    output = m.capture('ps', '-eo', 'pid=,ppid=,args=')
    for line in output.splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3:
            continue
        names = online.ssh_sessions(fields[2])
        if names:
            result['ssh:' + fields[1]] = names[0]
    for user, pid in dropbear_state.sessions():
        result['dropbear:' + str(pid)] = user
    try:
        data = json.loads(udp_runtime.STATE.read_text())
        if data.get('start') == udp_runtime.identity(data['pid']):
            result.update({'udp:' + key: user for key, user in data['connections'].items()})
    except (OSError, ValueError, KeyError):
        pass
    return result


@contextlib.contextmanager
def ledger():
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT / 'admission.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = ROOT / 'admission.json'
        data = json.loads(path.read_text()) if path.exists() else {}
        yield data
        temp = path.with_suffix('.new')
        temp.write_text(json.dumps(data))
        temp.chmod(0o600)
        os.replace(temp, path)


def remote(value):
    # OpenVPN 2.7 includes the transport in Real Address.
    return re.sub(r'^(?:tcp|udp)[46]?(?:-server|-client)?:', '', value)


def vpn_status():
    try:
        path = Path(online.STATUS_PATHS[0])
        if time.time() - path.stat().st_mtime > 30:
            return None
        rows = [line.split('\t') for line in path.read_text().splitlines()]
        return {'openvpn:' + remote(row[2]) for row in rows if len(row) > 2 and row[0] == 'CLIENT_LIST'}
    except FileNotFoundError:
        return None


def prune(data, live):
    now = time.time()
    vpn = vpn_status()
    for key, row in list(data.items()):
        info = process(row['pid'])
        gone = not info or info[1] != row['start']
        if now - row['created'] > 60:
            gone |= key.startswith('udp:') and key not in live
            gone |= key.startswith('openvpn:') and vpn is not None and key not in vpn
        if gone:
            del data[key]


def reserve(m, user, protocol, token, pid):
    m.managed(user)
    key = protocol + ':' + str(token)
    info = process(pid)
    if info is None:
        return False
    with ledger() as data:
        live = observed(m)
        prune(data, live)
        occupied = {**live, **{name: row['user'] for name, row in data.items()}}
        if key in occupied and occupied[key] != user:
            return False
        total = sum(owner == user for name, owner in occupied.items() if name != key)
        if m.load().get('limiter_enabled') and total >= accounts.load().get(user, {}).get('limit', 1):
            return False
        data[key] = {'user': user, 'pid': pid, 'start': info[1], 'created': data.get(key, {}).get('created', time.time())}
        return True


def release(protocol, token):
    with ledger() as data:
        data.pop(protocol + ':' + str(token), None)


def pam(m):
    user = os.environ.get('PAM_USER', '')
    # Distribution SSH PAM also serves administrators: never gate unmanaged users.
    if user not in m.users():
        return True
    pid = ssh_owner(os.getppid())
    return pid is not None and reserve(m, user, 'ssh', str(pid), pid)


def install(m):
    path = Path('/etc/pam.d/sshd')
    if path.exists():
        original = path.read_text()
        if PAM_LINE not in original:
            m.backup(path)
            m.write(path, original.rstrip() + '\n# VPN Manager managed accounts only\n' + PAM_SKIP + '\n' + PAM_LINE + '\n', 0o644)
    m.write('/etc/systemd/system/openvpn-server@vpnmanager.service.d/10-admission.conf', '[Unit]\nWants=vpnmanager-admission.service\nAfter=vpnmanager-admission.service\n', 0o644)
    m.service_unit('vpnmanager-admission', '/usr/bin/python3 /usr/local/lib/vpnmanager/admission.py serve', 'ReadWritePaths=/run')
    m.run('systemctl', 'daemon-reload')
    m.run('systemctl', 'enable', 'vpnmanager-admission')
    m.run('systemctl', 'restart', 'vpnmanager-admission')


def openvpn_options():
    return ('writepid /run/openvpn-server/vpnmanager.pid\nscript-security 2\n'
            + 'client-connect "' + HOOK + ' connect"\n'
            + 'client-disconnect "' + HOOK + ' disconnect"\n')


def refresh(m):
    install(m)
    path = Path('/etc/openvpn/server/vpnmanager.conf')
    if path.exists() and HOOK not in path.read_text():
        m.write(path, path.read_text().rstrip() + '\n' + openvpn_options())
        if 'openvpn' in m.load()['enabled']:
            m.run('systemctl', 'restart', m.SERVICES['openvpn'])


def request(data):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(SOCKET)
        connection.sendall(json.dumps(data).encode() + b'\n')
        with connection.makefile('rb') as stream:
            return json.loads(stream.readline(4096)).get('ok', False)


def openvpn_parent(pid):
    for _ in range(12):
        try:
            trusted = Path('/run/openvpn-server/vpnmanager.pid')
            if trusted.exists() and trusted.stat().st_uid == 0 and int(trusted.read_text().strip()) == pid and Path('/proc', str(pid), 'comm').read_text().strip() == 'openvpn':
                return pid
        except OSError:
            return None
        info = process(pid)
        if not info:
            return None
        pid = info[0]
    return None


def serve(m):
    directory = Path(SOCKET).parent
    directory.mkdir(mode=0o755, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        Path(SOCKET).unlink()
    class Handler(StreamRequestHandler):
        def handle(self):
            ok = False
            try:
                self.request.settimeout(3)
                peer, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                owner = openvpn_parent(peer)
                if owner is None:
                    self.wfile.write(b'{"ok":false}\n')
                    return
                data = json.loads(self.rfile.readline(4096))
                if owner is not None and data.get('protocol') == 'openvpn':
                    token = data['token']
                    if not isinstance(token, str) or not 1 <= len(token) <= 128 or '\n' in token:
                        raise ValueError('Invalid peer')
                    if data['action'] == 'disconnect':
                        release('openvpn', token)
                        ok = True
                    elif data['action'] == 'connect':
                        user = data['user']
                        m.managed(user)
                        shadow = m.capture('getent', 'shadow', user).split(':')
                        if not shadow[1].startswith(('!', '*')) and not accounts.expired(accounts.load().get(user, {}), shadow):
                            ok = reserve(m, user, 'openvpn', token, owner)
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                pass
            self.wfile.write(json.dumps({'ok': ok}).encode() + b'\n')
    class Server(ThreadingUnixStreamServer):
        daemon_threads = True
    with Server(SOCKET, Handler) as server:
        os.chmod(SOCKET, 0o666)  # A root-owned OpenVPN PID and peer ancestry are checked before any operation.
        server.serve_forever()


def enforce(m):
    """Fallback for lowered limits: remove newest excess sessions, preserving older ones."""
    if not m.load().get('limiter_enabled'):
        return
    with ledger() as data:
        live = observed(m)
        prune(data, live)
        all_sessions = {**live, **{key: row['user'] for key, row in data.items()}}
        excess = []
        for user, record in accounts.load().items():
            keys = [key for key, owner in all_sessions.items() if owner == user]
            keys.sort(key=lambda key:data.get(key, {}).get('created', 0))
            excess.extend(keys[max(1, int(record.get('limit', 1))):])
    restart_udp = False
    for key in excess:
        protocol, token = key.split(':', 1)
        if protocol in ('ssh', 'dropbear'):
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(token), signal.SIGTERM)
        elif protocol == 'openvpn':
            kill_openvpn(token)
        elif protocol == 'udp':
            restart_udp = True
    if restart_udp:
        # Hysteria v1 exposes no per-client kick. Reconnect through admission checks.
        m.run('systemctl', 'restart', m.SERVICES['udp'])



def kill_openvpn(token):
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(3)
        control.connect('/run/openvpn-server/vpnmanager.mgmt')
        control.recv(4096)
        control.sendall(b'status 3\n')
        with control.makefile('rb') as stream:
            rows = []
            size = 0
            while True:
                line = stream.readline(16384)
                size += len(line)
                if not line or size > 1024 * 1024:
                    raise ValueError('Incomplete OpenVPN management status')
                text = line.decode().strip()
                if text == 'END':
                    break
                rows.append(text.split('\t'))
            header = next((row for row in rows if row[:2] == ['HEADER','CLIENT_LIST']), [])
            entry = next((row for row in rows if len(row) > 2 and row[0] == 'CLIENT_LIST' and remote(row[2]) == token), None)
            if entry is None:
                release('openvpn', token)
                return
            index = header.index('Client ID') - 1 if 'Client ID' in header else None
            command = ('client-kill ' + entry[index]) if index is not None else ('kill ' + entry[2])
            control.sendall((command + '\n').encode())
            while True:
                response = stream.readline(16384)
                if response.startswith(b'SUCCESS:'):
                    return
                if not response or response.startswith(b'ERROR:'):
                    raise ValueError('OpenVPN rejected the per-client disconnect request')



if __name__ == '__main__':
    import sys
    import manager
    manager.root()
    if sys.argv[1:] == ['pam']:
        sys.exit(0 if pam(manager) else 1)
    elif sys.argv[1:] == ['serve']:
        serve(manager)
    else:
        sys.exit(2)
