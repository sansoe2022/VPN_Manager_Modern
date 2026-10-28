"""Count authenticated sessions, independent of client ISP or tunnel transport."""
import csv
import base64
import accounts
import profile_links
import dropbear_state
import udp_runtime
import backup_links
import grp
import pwd
import json
import re
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG_PATH = Path('/etc/vpnmanager/config.json')


def app_limit():
    try:
        value = json.loads(CONFIG_PATH.read_text()).get('online_app_limit', 2500)
    except FileNotFoundError:
        value = 2500
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 2147483647:
        raise ValueError('Invalid Online App limit')
    return value


STATUS_PATHS = (
    '/run/openvpn-server/vpnmanager.status',
    '/etc/openvpn/server/openvpn-status.log',
    '/etc/openvpn/openvpn-status.log',
)


def ssh_sessions(output):
    # Count one post-authentication process per connection; exclude priv/monitor
    # processes and the root server listener. New OpenSSH uses sshd-session.
    sessions = []
    for line in output.splitlines():
        match = re.search(r'^\s*sshd(?:-session)?: ([a-z_][a-z0-9_-]*)(?:@(?:pts/\d+|notty)\b|\s*$)', line)
        if match:
            sessions.append(match[1])
    return sessions


def openvpn_sessions(text):
    # OpenVPN status-version 2 uses CSV; version 3 uses tabs. Ignore headers,
    # routes and summary records, which used to be counted as clients.
    sessions = []
    for line in text.splitlines():
        row = next(csv.reader([line], delimiter='\t' if '\t' in line else ','))
        if row and row[0] == 'CLIENT_LIST' and len(row) >= 3:
            sessions.append(row[1])
    return sessions


def collect():
    result = subprocess.run(['ps', '-eo', 'args='], capture_output=True, text=True, check=True)
    try:
        group = grp.getgrnam('vpnmanager')
        managed = set(group.gr_mem) | {entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == group.gr_gid}
    except KeyError:
        managed = set()
    ssh = [name for name in ssh_sessions(result.stdout) if name in managed]
    vpn = []
    source = None
    for filename in STATUS_PATHS:
        try:
            path = Path(filename)
            vpn = [name for name in openvpn_sessions(path.read_text()) if name in managed]
            source = {'path': filename, 'age_seconds': max(0, int(time.time() - path.stat().st_mtime))}
            # A stopped daemon can leave a stale status file behind.
            if source['age_seconds'] > 60:
                vpn = []
            break
        except FileNotFoundError:
            continue
    drop = [name for name, _ in dropbear_state.sessions() if name in managed]
    udp = [name for name in udp_runtime.sessions() if name in managed]
    return {'ssh': len(ssh), 'dropbear': len(drop), 'openvpn': len(vpn), 'udp': len(udp), 'total': len(ssh) + len(drop) + len(vpn) + len(udp),
            'users': {'ssh': ssh, 'dropbear': drop, 'openvpn': vpn, 'udp': udp}, 'openvpn_status': source}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path.startswith('/backups/'):
            self.download_backup(path)
            return
        if path.startswith('/profiles/'):
            self.download_profile(path)
            return
        if path == '/checkuser':
            self.check_user()
            return
        if path not in ('/server/online_app', '/server/online', '/online', '/health', '/udpserver/online', '/udpserver/online_app'):
            self.send_error(404, 'Unknown endpoint')
            return
        try:
            data = collect()
            if path == '/health':
                body = b'{"status":"ok"}'
            elif path.endswith('online_app'):
                # Preserve the legacy app's field names and string values.
                body = json.dumps({'onlines': str(data['total']), 'limite': str(app_limit())}).encode()
            else:
                body = str(data['total']).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json' if path.endswith(('online_app', 'health')) else 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        except (OSError, ValueError, subprocess.SubprocessError):
            self.send_error(503, 'Session data is unavailable')

    def log_request(self, code='-', size='-'):
        if getattr(self, 'path', '').startswith(('/profiles/', '/backups/')):
            # Do not put bearer download tokens in the journal/access log.
            prefix = '/backups/' if self.path.startswith('/backups/') else '/profiles/'
            self.log_message('"%s %s[redacted] %s" %s %s', self.command, prefix, self.request_version, str(code), str(size))
        else:
            super().log_request(code, size)

    def do_HEAD(self):
        path = self.path.split('?', 1)[0]
        if path.startswith('/backups/'):
            self.download_backup(path, head=True)
        elif path.startswith('/profiles/'):
            self.download_profile(path, head=True)
        else:
            self.send_error(405, 'Use GET for this endpoint')

    def download_backup(self, path, head=False):
        source = backup_links.resolve(path)
        if source is None:
            self.send_error(404, 'Download link is invalid or expired')
            return
        with source.open('rb') as file:
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="backup.vpnbak"')
            self.send_header('Content-Length', str(source.stat().st_size))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            if not head:
                while True:
                    block = file.read(1024 * 1024)
                    if not block:
                        break
                    self.wfile.write(block)

    def download_profile(self, path, head=False):
        body = profile_links.read(path)
        if body is None:
            self.send_error(404, 'Download link is invalid or expired')
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-openvpn-profile')
        self.send_header('Content-Disposition', 'attachment; filename="client.ovpn"')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def check_user(self):
        try:
            config = json.loads(CONFIG_PATH.read_text())
            if not config.get('checkuser'):
                self.send_error(404, 'Unknown endpoint')
                return
            header = self.headers.get('Authorization', '')
            if not header.startswith('Basic ') or len(header) > 2048:
                raise ValueError('Authentication required')
            username, secret = base64.b64decode(header[6:], validate=True).decode().split(':', 1)
            group = grp.getgrnam('vpnmanager')
            user = pwd.getpwnam(username)
            if username not in group.gr_mem and user.pw_gid != group.gr_gid:
                raise ValueError('Unknown account')
            if not accounts.verify_password(username, secret):
                raise ValueError('Invalid credentials')
            result = subprocess.run(['getent', 'shadow', username], capture_output=True, text=True, check=True)
            fields = result.stdout.split(':')
            record = accounts.load().get(username, {})
            status = 'expired' if accounts.expired(record, fields) else 'locked' if fields[1].startswith(('!', '*')) else 'active'
            data = collect()
            count = sum(names.count(username) for names in data['users'].values())
            body = json.dumps({'username': username, 'status': status, 'online': count,
                               'limit': record.get('limit', 1), 'expires_at': record.get('expires_at'),
                               'expiry_day': fields[7] or None}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        except (ValueError, UnicodeError, KeyError):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="CheckUser"')
            self.send_header('Content-Length', '0')
            self.end_headers()
        except (OSError, subprocess.SubprocessError):
            self.send_error(503, 'Account data is unavailable')


def serve(host, port):
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 128

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(10)
            return connection, address

    Server((host, port), Handler).serve_forever()
