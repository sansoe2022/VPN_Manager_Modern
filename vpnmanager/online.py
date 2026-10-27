"""Count authenticated sessions, independent of client ISP or tunnel transport."""
import csv
import grp
import pwd
import json
import re
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
    return {'ssh': len(ssh), 'openvpn': len(vpn), 'total': len(ssh) + len(vpn),
            'users': {'ssh': ssh, 'openvpn': vpn}, 'openvpn_status': source}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path not in ('/server/online_app', '/server/online', '/online', '/health'):
            self.send_error(404, 'Unknown endpoint')
            return
        try:
            data = collect()
            if path == '/health':
                body = b'{"status":"ok"}'
            elif path.endswith('online_app'):
                # Preserve the legacy app's field names and string values.
                body = json.dumps({'onlines': str(data['total']), 'limite': '2500'}).encode()
            else:
                body = str(data['total']).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json' if path.endswith(('online_app', 'health')) else 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        except (OSError, subprocess.SubprocessError):
            self.send_error(503, 'Session data is unavailable')


def serve(host, port):
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 128

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(10)
            return connection, address

    Server((host, port), Handler).serve_forever()
