"""Hysteria v1 integration with the manager's accounts and shared online totals."""
import base64
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import threading
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
    directory = Path('/etc/vpnmanager')
    cert, key = directory / 'udp-ca.crt', directory / 'udp-server.key'
    endpoint = m.endpoint(config['endpoint'])
    if not cert.exists() or not key.exists():
        san = ('IP:' if ':' in endpoint or endpoint.replace('.', '').isdigit() else 'DNS:') + endpoint
        m.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
              '-subj', '/CN=' + endpoint, '-addext', 'subjectAltName=' + san, '-keyout', str(key), '-out', str(cert))
        key.chmod(0o600)
    data = {'listen': f'{config.get("host", "0.0.0.0")}:{number}', 'protocol': 'udp', 'cert': str(cert), 'key': str(key),
            'up_mbps': config.get('udp_up_mbps', 100), 'down_mbps': config.get('udp_down_mbps', 100),
            'obfs': config.get('udp_obfs', ''), 'auth': {'mode': 'external', 'config': {}}}
    m.write(CONFIG, json.dumps(data, indent=2))
    print('[2/3] Configuring shared account authentication...', flush=True)
    config['udp_port'] = number
    config.setdefault('udp_server_name', endpoint)
    m.save(config)
    m.service_unit('vpnmanager-udp', '/usr/local/bin/vpnmanager serve-udp', 'ReadWritePaths=/run')
    m.start('udp', config)
    print('[3/3] UDP enabled. Existing SSH/OpenVPN users can authenticate as username:password.', flush=True)


def serve(m):
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
                            del pending[old]
                    if len(pending) >= 4096:
                        username = None
                    if username and m.load().get('limiter_enabled'):
                        total = sum(names.count(username) for names in m.collect()['users'].values())
                        reserved = sum(value[0] == username for value in pending.values())
                        if total + reserved >= accounts.load().get(username, {}).get('limit', 1):
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
