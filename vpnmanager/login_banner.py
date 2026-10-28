"""Deliver the configured login message over SSH and OpenVPN's ECHO channel."""
from pathlib import Path
import subprocess

BANNER = Path('/etc/vpnmanager/banner')
MARKER = '# VPN Manager login banner'


def openvpn_option(value):
    # One quoted option, no new directives even for pasted HTML or multiline text.
    if any(ord(char) < 32 and not char.isspace() for char in value):
        raise ValueError('Banner contains invalid control characters.')
    value = ' '.join(value.split()).replace(',', '&#44;').replace('\\', '\\\\').replace('"', '\\"')
    if len(value.encode()) > 1800:
        raise ValueError('Banner is too long for OpenVPN (maximum 1800 encoded bytes).')
    return 'push "echo ' + value + '"' if value else ''


def apply(m, value):
    option = openvpn_option(value)
    BANNER.parent.mkdir(parents=True, exist_ok=True)
    previous = BANNER.read_text() if BANNER.exists() else ''
    m.write(BANNER, value + '\n', 0o644)
    paths = [Path('/etc/ssh/sshd_config'), Path('/etc/vpnmanager/sshd_config')]
    updated = []
    try:
        for path in paths:
            if not path.exists():
                continue
            original = path.read_text()
            # Must precede Include/Match, and existing Banner directives. OpenSSH uses first value.
            clean = '\n'.join(line for line in original.splitlines() if line != MARKER)
            lines = clean.splitlines()
            if lines and lines[0] == 'Banner /etc/vpnmanager/banner':
                lines.pop(0)
            m.write(path, MARKER + '\nBanner /etc/vpnmanager/banner\n' + '\n'.join(lines) + '\n', 0o644 if path == paths[0] else 0o600)
            updated.append((path, original))
            m.run('/usr/sbin/sshd', '-t', '-f', str(path))
    except (OSError, subprocess.SubprocessError):
        for path, original in updated:
            m.write(path, original, 0o644 if path == paths[0] else 0o600)
        m.write(BANNER, previous, 0o644)
        raise
    if paths[0].exists():
        # Debian/Ubuntu name the distribution service ssh.service.
        m.run('systemctl', 'reload-or-restart', 'ssh.service')
    if paths[1].exists():
        m.run('systemctl', 'reload-or-restart', 'vpnmanager-sshd')
    if 'dropbear' in m.load()['enabled']:
        m.run('systemctl', 'restart', 'vpnmanager-dropbear')
    server = Path('/etc/openvpn/server/vpnmanager.conf')
    if server.exists():
        rows = [line for line in server.read_text().splitlines() if not line.startswith('push "echo ')]
        m.write(server, '\n'.join(rows) + '\n' + (option + '\n' if option else ''))
        if 'openvpn' in m.load()['enabled']:
            m.run('systemctl', 'restart', m.SERVICES['openvpn'])
    print('SSH port 22/dedicated SSH and Dropbear send a login banner.')
    print('OpenVPN sends ECHO after authentication; display depends on the client app.')
