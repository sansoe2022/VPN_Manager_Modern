"""Hysteria v1 integration with the manager's accounts and shared online totals."""
import base64
import json
import os
import ipaddress
from pathlib import Path
import platform
import signal
import secrets
import shutil
import subprocess
import sys
import threading
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import accounts
import downloads

BINARY = Path('/usr/local/lib/vpnmanager/bin/hysteria')
CONFIG = Path('/etc/vpnmanager/udp.json')
STATE = Path('/run/vpnmanager/udp-sessions.json')
HASHES = {'amd64': '41dc8bc3fff6fc1f031666eb294f10b481b80b66229d7c6aca88398d0fba839d',
          'arm64': '702cd2f3f7bb1d00d463ece4547b6a80de85aa4f6fa8fd1dc7ebd87eb0e2c7b9'}


def identity(pid):
    try:
        return Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, ValueError, IndexError):
        return None


def sessions():
    try:
        data = json.loads(STATE.read_text())
        if not data.get('start') or identity(data['pid']) != data['start']:
            return []
        return list(data['connections'].values())
    except (OSError, ValueError, KeyError, TypeError):
        return []


def authenticate(m, request):
    try:
        raw = base64.b64decode(request['payload'], validate=True)
        if len(raw) > 2048:
            return None
        username, password = raw.decode().split(':', 1)
        m.managed(username)
        shadow = m.capture('getent', 'shadow', username).split(':')
        record = accounts.load().get(username, {})
        if shadow[1].startswith(('!', '*')) or accounts.expired(record, shadow):
            return None
        return username if accounts.verify_password(username, password) else None
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError):
        return None


def certificates(m, endpoint, directory=Path('/etc/vpnmanager')):
    """Retain the CA/keys while issuing a leaf certificate for the current endpoint."""
    directory.mkdir(parents=True, exist_ok=True)
    ca, ca_key = directory / 'udp-ca.crt', directory / 'udp-ca.key'
    key, leaf = directory / 'udp-server.key', directory / 'udp-server.crt'
    if not ca.exists():
        with tempfile.TemporaryDirectory(prefix='vpnmanager-udp-ca-') as temporary:
            settings = Path(temporary) / 'ca.conf'
            settings.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=VPN Manager UDP CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
            m.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650', '-sha256',
                  '-config', str(settings), '-keyout', str(ca_key), '-out', str(ca))
        ca_key.chmod(0o600)
        ca.chmod(0o600)
    else:
        public = m.capture('openssl', 'x509', '-in', str(ca), '-noout', '-pubkey')
        signing_matches = ca_key.exists() and public == m.capture('openssl', 'pkey', '-in', str(ca_key), '-pubout')
        # Previous Modern installs used the same self-signed key as CA/server.
        if not signing_matches:
            details = m.capture('openssl', 'x509', '-in', str(ca), '-noout', '-text')
            if not key.exists() or 'CA:TRUE' not in details:
                raise ValueError('UDP CA signing key is missing. Restore the complete UDP CA/key backup.')
            if public != m.capture('openssl', 'pkey', '-in', str(key), '-pubout'):
                raise ValueError('The legacy UDP CA and server private key do not match.')
            shutil.copy2(key, ca_key)
            ca_key.chmod(0o600)
    if not key.exists():
        m.run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key))
        key.chmod(0o600)
    try:
        ipaddress.ip_address(endpoint)
        kind, check = 'IP', '-checkip'
    except ValueError:
        kind, check = 'DNS', '-checkhost'
    matches = leaf.exists() and subprocess.run(['openssl', 'x509', '-in', str(leaf), '-noout', check, endpoint],
                                              capture_output=True).returncode == 0
    if matches:
        matches = subprocess.run(['openssl', 'verify', '-purpose', 'sslserver', '-CAfile', str(ca), str(leaf)],
                                 capture_output=True).returncode == 0
        matches = matches and m.capture('openssl', 'x509', '-in', str(leaf), '-noout', '-pubkey') == m.capture('openssl', 'pkey', '-in', str(key), '-pubout')
    if not matches:
        print('Updating UDP certificate for ' + endpoint + '...', flush=True)
        with tempfile.TemporaryDirectory(prefix='vpnmanager-udp-cert-') as temporary:
            csr, extensions = Path(temporary) / 'server.csr', Path(temporary) / 'server.ext'
            m.run('openssl', 'req', '-new', '-key', str(key), '-subj', '/CN=' + endpoint, '-out', str(csr))
            extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=' + kind + ':' + endpoint + '\n')
            candidate = leaf.with_name(leaf.name + '.new')
            try:
                m.run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key),
                      '-set_serial', str(secrets.randbits(159) + 1), '-days', '3650', '-sha256',
                      '-extfile', str(extensions), '-out', str(candidate))
                candidate.chmod(0o600)
                m.run('openssl', 'verify', '-CAfile', str(ca), str(candidate))
                os.replace(candidate, leaf)
            finally:
                candidate.unlink(missing_ok=True)
    return leaf, key


def configure(m, config, number):
    number = m.port(number)
    if 'udp' not in config['enabled'] or number != config.get('udp_port'):
        if m.capture('ss', '-H', '-lun', 'sport', '=', str(number)):
            raise ValueError(f'UDP port {number} is in use.')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if arch not in HASHES:
        raise ValueError('UDP integration currently supports amd64 and arm64.')
    if not BINARY.exists():
        print('[1/3] Downloading Hysteria v1.3.5 (no license key)...', flush=True)
        downloads.fetch(f'https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-{arch}', BINARY, 64 * 1024 * 1024, HASHES[arch])
        BINARY.chmod(0o755)
    endpoint = m.endpoint(config['endpoint'])
    cert, key = certificates(m, endpoint)
    data = {'listen': f'{config.get("host", "0.0.0.0")}:{number}', 'protocol': 'udp', 'cert': str(cert), 'key': str(key),
            'up_mbps': config.get('udp_up_mbps', 100), 'down_mbps': config.get('udp_down_mbps', 100),
            'obfs': config.get('udp_obfs') or 'svpn', 'auth': {'mode': 'external', 'config': {}}}
    m.write(CONFIG, json.dumps(data, indent=2))
    print('[2/3] Configuring shared account authentication...', flush=True)
    config['udp_obfs'] = data['obfs']
    config.setdefault('udp_port_range', '10000-65000')
    config['udp_port'] = number
    config['udp_server_name'] = endpoint
    m.save(config)
    m.service_unit('vpnmanager-udp', '/usr/local/bin/vpnmanager serve-udp', 'ReadWritePaths=/run')
    m.start('udp', config)
    print('[3/3] UDP enabled. Existing SSH/OpenVPN users can authenticate as username:password.', flush=True)


def hopping(m, config, remove=False):
    """Own only our NAT chain; preserve ports already bound by other UDP services."""
    chain = 'VPNMANAGER_UDP'
    tools = ['iptables']
    if Path('/proc/net/if_inet6').exists() and Path('/proc/net/if_inet6').read_text().strip():
        tools.append('ip6tables')
    for tool in tools:
        def call(*args, required=True):
            result = subprocess.run([tool, '-w', '5', '-t', 'nat', *args], capture_output=True, text=True)
            if required and result.returncode:
                raise ValueError(f'UDP port hopping: {tool}: {result.stderr.strip()}')
            return result.returncode == 0
        if tool == 'ip6tables' and not call('-L', required=False):
            if not remove:
                print('IPv6 NAT unavailable; UDP hopping remains available over IPv4.', flush=True)
            continue
        if remove:
            if call('-C', 'PREROUTING', '-p', 'udp', '-j', chain, required=False):
                call('-D', 'PREROUTING', '-p', 'udp', '-j', chain)
            call('-F', chain, required=False)
            call('-X', chain, required=False)
            continue
        number = m.port(config['udp_port'])
        low, high = map(int, config.get('udp_port_range', '10000-65000').split('-'))
        if not 1 <= low <= high <= 65535:
            raise ValueError('Invalid UDP hopping range.')
        call('-N', chain, required=False)
        call('-F', chain)
        output = m.capture('ss', '-H', '-lun')
        ports = set()
        for line in output.splitlines():
            try:
                ports.add(int(line.split()[3].rsplit(':', 1)[1]))
            except (ValueError, IndexError):
                continue
        for port in sorted(ports - {number}):
            if low <= port <= high:
                call('-A', chain, '-p', 'udp', '--dport', str(port), '-j', 'RETURN')
        call('-A', chain, '-p', 'udp', '--dport', f'{low}:{high}', '-j', 'REDIRECT', '--to-ports', str(number))
        if not call('-C', 'PREROUTING', '-p', 'udp', '-j', chain, required=False):
            call('-A', 'PREROUTING', '-p', 'udp', '-j', chain)


def serve(m):
    config = m.load()
    try:
        hopping(m, config)
        return _serve(m)
    finally:
        hopping(m, config, remove=True)


def _serve(m):
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending, connected = {}, {}
    lock = threading.RLock()
    def save():
        m.write(STATE, json.dumps({'pid': os.getpid(), 'start': identity(os.getpid()), 'connections': connected}))
    save()
    class Auth(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log credentials or authentication payloads.
        def do_POST(self):
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if self.path != '/auth' or not 0 < size <= 8192:
                    raise ValueError('Invalid authentication request')
                request = json.loads(self.rfile.read(size))
                username = authenticate(m, request)
                addr = request.get('addr', '')
                if not isinstance(addr, str) or len(addr) > 128:
                    username = None
                with lock:
                    now = time.monotonic()
                    for old in list(pending):
                        if pending[old][1] < now - 15:
                            import admission
                            admission.release('udp', old)
                            del pending[old]
                    if len(pending) >= 4096:
                        username = None
                    if username:
                        import admission
                        if not admission.reserve(m, username, 'udp', addr, os.getpid()):
                            username = None
                    if username:
                        pending[addr] = (username, now)
                body = json.dumps({'ok': bool(username), 'msg': 'Welcome' if username else 'Authentication failed'}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ValueError, KeyError, TypeError):
                self.send_error(400)
    auth_server = ThreadingHTTPServer(('127.0.0.1', 0), Auth)
    auth_server.daemon_threads = True
    thread = threading.Thread(target=auth_server.serve_forever, daemon=True)
    thread.start()
    data = json.loads(CONFIG.read_text())
    data['auth'] = {'mode': 'external', 'config': {'http': f'http://127.0.0.1:{auth_server.server_port}/auth'}}
    runtime = STATE.parent / 'udp-runtime.json'
    m.write(runtime, json.dumps(data))
    process = subprocess.Popen([str(BINARY), '--no-check', '--log-format', 'json', '--log-level', 'info',
                                'server', '-c', str(runtime)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    def stop(*args):
        if process.poll() is None:
            process.terminate()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, stop)
    try:
        for line in process.stdout:
            try:
                event = json.loads(line)
                addr, message = event.get('src'), event.get('msg', '')
                with lock:
                    if message == 'Client connected' and addr in pending:
                        connected[addr] = pending.pop(addr)[0]
                        save()
                    elif message == 'Client disconnected':
                        import admission
                        admission.release('udp', addr)
                        connected.pop(addr, None)
                        pending.pop(addr, None)
                        save()
                # Only known diagnostic fields; no auth strings/metrics are published.
                if message in ('Server up and running', 'Server shutdown', 'Failed to load server config') or event.get('level') in ('error', 'fatal'):
                    print(message + ': ' + str(event.get('error', '')), flush=True)
            except (ValueError, TypeError):
                continue
        return process.wait()
    finally:
        stop()
        process.wait(timeout=5)
        with lock:
            connected.clear()
            save()
        auth_server.shutdown()
        auth_server.server_close()
        thread.join()
