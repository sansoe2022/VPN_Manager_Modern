#!/usr/bin/env python3
"""Readable VPN Manager CLI for Ubuntu 22.04+ and Debian 12+."""
import argparse
import asyncio
import datetime as dt
import fcntl
import getpass
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tarfile

from online import collect, serve as online_serve
from tunnel import serve as tunnel_serve

CONFIG = Path('/etc/vpnmanager/config.json')
STATE = Path('/var/lib/vpnmanager')
GROUP = 'vpnmanager'
DEFAULTS = {'host': '0.0.0.0', 'ssh_port': 22, 'tunnel_port': 80, 'tls_port': 443,
            'online_port': 81, 'squid_port': 3128, 'openvpn_port': 1194,
            'endpoint': '', 'squid_networks': ['127.0.0.1/32'], 'enabled': []}
SERVICES = {'tunnel': 'vpnmanager-tunnel', 'tls': 'vpnmanager-tls',
            'online': 'vpnmanager-online', 'squid': 'squid',
            'openvpn': 'openvpn-server@vpnmanager'}


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, text=True, **kwargs)


def capture(*args):
    return run(*args, capture_output=True).stdout.strip()


def root():
    if os.geteuid() != 0:
        raise ValueError('Run this command as root (sudo vpnmanager).')


def load():
    return {**DEFAULTS, **json.loads(CONFIG.read_text())} if CONFIG.exists() else dict(DEFAULTS)


def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.new')
    temp.write_text(text)
    temp.chmod(mode)
    os.replace(temp, path)


def save(config):
    write(CONFIG, json.dumps(config, indent=2) + '\n')


def backup(path):
    path = Path(path)
    if path.exists():
        dest = STATE / 'backups' / (path.name + '.before-vpnmanager')
        if not dest.exists():
            shutil.copy2(path, dest)


def service_unit(name, command, extra=''):
    write('/etc/systemd/system/' + name + '.service', f'''[Unit]
Description=VPN Manager {name}
After=network.target
[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
{extra}
[Install]
WantedBy=multi-user.target
''', 0o644)


def initialize():
    root()
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / 'backups').mkdir(exist_ok=True)
    try:
        grp.getgrnam(GROUP)
    except KeyError:
        run('groupadd', '--system', GROUP)
    if not CONFIG.exists():
        save(dict(DEFAULTS))
    service_unit('vpnmanager-online', '/usr/local/bin/vpnmanager serve-online')
    service_unit('vpnmanager-tunnel', '/usr/local/bin/vpnmanager serve-tunnel')
    service_unit('vpnmanager-tls', '/usr/bin/stunnel /etc/vpnmanager/stunnel.conf')
    # A private service instance avoids changing the administrator's SSH listener.
    service_unit('vpnmanager-sshd', '/usr/sbin/sshd -D -f /etc/vpnmanager/sshd_config',
                 'ExecStartPre=/usr/bin/install -d -m 0755 /run/sshd\nReadWritePaths=/run')
    write('/etc/systemd/system/vpnmanager-expire.service', '''[Unit]
Description=Disconnect expired VPN Manager accounts
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnmanager expire
''', 0o644)
    write('/etc/systemd/system/vpnmanager-expire.timer', '''[Unit]
Description=Check VPN Manager account expiry every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
''', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'vpnmanager-expire.timer')
    print('Initialized. Existing administrator SSH and firewall settings are preserved.')


def valid_user(username):
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', username):
        raise ValueError('Use 1-31 lowercase letters, digits, underscores or hyphens; start with a letter.')
    return username


def users():
    members = set(grp.getgrnam(GROUP).gr_mem)
    gid = grp.getgrnam(GROUP).gr_gid
    return [entry.pw_name for entry in pwd.getpwall() if entry.pw_name in members or entry.pw_gid == gid]


def managed(username):
    valid_user(username)
    if username not in users():
        raise ValueError('This account is not managed by VPN Manager.')


def password(username):
    first = getpass.getpass('New password: ')
    if len(first) < 10 or ':' in first or '\n' in first or '\r' in first:
        raise ValueError('Use at least 10 characters, without colons or newlines.')
    if first != getpass.getpass('Repeat password: '):
        raise ValueError('Passwords do not match.')
    run('chpasswd', input=f'{username}:{first}\n')


def expiry(username, days):
    if not 1 <= days <= 3650:
        raise ValueError('Validity must be between 1 and 3650 days.')
    date = dt.date.today() + dt.timedelta(days=days)
    run('chage', '-E', date.isoformat(), username)
    print(f'{username} expires on {date} (server date).')


def create_user(username, days):
    valid_user(username)
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise ValueError('That system account already exists.')
    # No shell access; SSH TCP forwarding uses -N and the dedicated SSH service.
    run('useradd', '-M', '-g', GROUP, '-s', '/usr/sbin/nologin', username)
    try:
        password(username)
        expiry(username, days)
    except BaseException:
        run('userdel', username)
        raise
    print('Account created. SSH clients must use forwarding / no-session mode.')


def disconnect(username):
    managed(username)
    result = subprocess.run(['pkill', '-TERM', '-u', username], check=False)
    if result.returncode not in (0, 1):
        raise ValueError('Unable to disconnect SSH sessions.')
    # OpenVPN runs as nobody, so disconnect it via the local management socket.
    sockpath = '/run/openvpn-server/vpnmanager.mgmt'
    if Path(sockpath).exists():
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(sockpath)
            connection.recv(4096)
            connection.sendall(f'kill {username}\nquit\n'.encode())
            connection.recv(4096)


def expire_portable():
    # Python 3.13 removed spwd. Read shadow through getent, without logging it.
    today = (dt.date.today() - dt.date(1970, 1, 1)).days
    for username in users():
        fields = capture('getent', 'shadow', username).split(':')
        if (fields[7] and int(fields[7]) <= today) or fields[1].startswith(('!', '*')):
            disconnect(username)


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    return number


def free_port(number):
    # Check both IPv4 and IPv6 listeners, including systemd socket activation.
    output = capture('ss', '-H', '-ltn', 'sport', '=', str(number))
    if output:
        raise ValueError(f'TCP port {number} is in use. Stop its owner or choose another port.')


def start(name, config):
    unit = SERVICES[name]
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', unit)
    run('systemctl', 'restart', unit)
    run('systemctl', 'is-active', '--quiet', unit)
    config['enabled'] = sorted(set(config['enabled']) | {name})
    save(config)
    print(f'{name} started. Allow its TCP port in your host and provider firewall if needed.')


def configure_ssh(config, number):
    if number == config['ssh_port'] and Path('/etc/vpnmanager/sshd_config').exists():
        run('systemctl', 'restart', 'vpnmanager-sshd')
        return
    free_port(number)
    Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
    run('ssh-keygen', '-A')
    text = f'''Port {number}
ListenAddress 127.0.0.1
PidFile /run/vpnmanager-sshd.pid
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowGroups {GROUP}
AllowTcpForwarding yes
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
ForceCommand /bin/false
ClientAliveInterval 60
ClientAliveCountMax 3
Subsystem sftp internal-sftp
'''
    temp = Path('/etc/vpnmanager/sshd_config.check')
    write(temp, text)
    run('/usr/sbin/sshd', '-t', '-f', str(temp))
    os.replace(temp, '/etc/vpnmanager/sshd_config')
    config['ssh_port'] = number
    save(config)
    run('systemctl', 'enable', '--now', 'vpnmanager-sshd')
    run('systemctl', 'restart', 'vpnmanager-sshd')
    if 'tunnel' in config['enabled']:
        run('systemctl', 'restart', SERVICES['tunnel'])
    if 'squid' in config['enabled']:
        configure('squid', config, config['squid_port'])
    print('Dedicated SSH backend listens on loopback; administrator SSH is unchanged.')


def squid_config(config):
    networks = [str(ipaddress.ip_network(value, strict=False)) for value in config['squid_networks']]
    if not networks:
        raise ValueError('At least one allowed client IP/CIDR is required.')
    # Only local VPN backends are reachable, including CONNECT on SSH/OpenVPN.
    return f'''http_port {config['squid_port']}
visible_hostname vpnmanager
acl manager_clients src {' '.join(networks)}
acl vpn_backend dst 127.0.0.1/32
acl vpn_ports port {config['ssh_port']} {config['openvpn_port']} {config['tunnel_port']}
http_access allow manager_clients vpn_ports vpn_backend
http_access deny all
cache deny all
forwarded_for delete
via off
'''


def configure(name, config, number):
    number = port(number)
    if name not in SERVICES:
        raise ValueError('Unknown service.')
    old_port = config[name + '_port']
    if name not in config['enabled'] or old_port != number:
        # Distribution packages may already start their default listener.
        if name == 'squid' and number == 3128 and name not in config['enabled']:
            run('systemctl', 'stop', 'squid')
        free_port(number)
    config[name + '_port'] = number
    if name == 'squid':
        path = Path('/etc/squid/squid.conf')
        backup(path)
        candidate = path.with_name('vpnmanager-check.conf')
        write(candidate, squid_config(config), 0o644)
        run('squid', '-k', 'parse', '-f', str(candidate))
        os.replace(candidate, path)
    elif name == 'tls':
        cert = Path('/etc/vpnmanager/tls.pem')
        if not cert.exists():
            run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '365',
                '-subj', '/CN=VPN-Manager', '-keyout', '/etc/vpnmanager/tls.key',
                '-out', '/etc/vpnmanager/tls.crt')
            write(cert, Path('/etc/vpnmanager/tls.key').read_text() + Path('/etc/vpnmanager/tls.crt').read_text())
        if 'tunnel' not in config['enabled']:
            raise ValueError('Enable the HTTP/WebSocket tunnel first. TLS wraps that tunnel.')
        write('/etc/vpnmanager/stunnel.conf', f'''foreground = yes
pid =
cert = {cert}
sslVersionMin = TLSv1.2
[https-tunnel]
accept = {config['host']}:{number}
connect = 127.0.0.1:{config['tunnel_port']}
''')
    elif name == 'tunnel':
        if not Path('/etc/vpnmanager/sshd_config').exists():
            raise ValueError('Configure the dedicated SSH backend first.')
    elif name == 'openvpn':
        setup_openvpn(config)
    save(config)
    start(name, config)
    if name in ('tunnel', 'openvpn') and 'squid' in config['enabled']:
        configure('squid', config, config['squid_port'])
    if name == 'tunnel' and 'tls' in config['enabled']:
        configure('tls', config, config['tls_port'])


def setup_openvpn(config):
    if not Path('/dev/net/tun').exists():
        raise ValueError('The host must provide /dev/net/tun for OpenVPN.')
    directory = Path('/etc/openvpn/server')
    directory.mkdir(parents=True, exist_ok=True)
    pki = Path('/etc/vpnmanager/pki')
    env = {**os.environ, 'EASYRSA_PKI': str(pki), 'EASYRSA_BATCH': '1',
           'EASYRSA_REQ_CN': 'VPN-Manager-CA', 'EASYRSA_ALGO': 'ec', 'EASYRSA_CURVE': 'prime256v1'}
    if not (pki / 'ca.crt').exists():
        run('/usr/share/easy-rsa/easyrsa', 'init-pki', env=env)
        run('/usr/share/easy-rsa/easyrsa', 'build-ca', 'nopass', env=env)
    if not (pki / 'issued/server.crt').exists():
        run('/usr/share/easy-rsa/easyrsa', 'build-server-full', 'server', 'nopass',
            env={key: value for key, value in env.items() if key != 'EASYRSA_REQ_CN'})
    for source, destination in ((pki / 'ca.crt', directory / 'vpnmanager-ca.crt'),
                                (pki / 'issued/server.crt', directory / 'vpnmanager-server.crt'),
                                (pki / 'private/server.key', directory / 'vpnmanager-server.key')):
        shutil.copy2(source, destination)
        destination.chmod(0o600)
    key = directory / 'vpnmanager-tls.key'
    if not key.exists():
        run('openvpn', '--genkey', 'secret', str(key))
        key.chmod(0o600)
    plugins = list(Path('/usr/lib').glob('**/openvpn-plugin-auth-pam.so'))
    if not plugins:
        raise ValueError('Distribution OpenVPN PAM plugin was not found.')
    write('/etc/pam.d/vpnmanager', '''auth requisite pam_succeed_if.so user ingroup vpnmanager
auth required pam_unix.so
account required pam_unix.so
''', 0o644)
    write(directory / 'vpnmanager.conf', f'''port {config['openvpn_port']}
proto tcp-server
dev tun-vpnmanager
topology subnet
server 10.80.0.0 255.255.255.0
ca vpnmanager-ca.crt
cert vpnmanager-server.crt
key vpnmanager-server.key
dh none
tls-crypt vpnmanager-tls.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verify-client-cert none
username-as-common-name
plugin {plugins[0]} vpnmanager
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 9.9.9.9"
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
status /run/openvpn-server/vpnmanager.status 10
status-version 3
management /run/openvpn-server/vpnmanager.mgmt unix
management-client-user root
verb 3
''')
    write('/etc/sysctl.d/90-vpnmanager.conf', 'net.ipv4.ip_forward=1\n', 0o644)
    run('sysctl', '-p', '/etc/sysctl.d/90-vpnmanager.conf')
    # Dedicated chains; never flush the host firewall or disable UFW.
    write('/usr/local/lib/vpnmanager/firewall.sh', '''#!/usr/bin/env bash
set -euo pipefail
iptables -t nat -N VPNMANAGER_NAT 2>/dev/null || true
iptables -t nat -C VPNMANAGER_NAT -s 10.80.0.0/24 ! -d 10.80.0.0/24 -j MASQUERADE 2>/dev/null || iptables -t nat -A VPNMANAGER_NAT -s 10.80.0.0/24 ! -d 10.80.0.0/24 -j MASQUERADE
iptables -t nat -C POSTROUTING -j VPNMANAGER_NAT 2>/dev/null || iptables -t nat -A POSTROUTING -j VPNMANAGER_NAT
iptables -N VPNMANAGER_FWD 2>/dev/null || true
iptables -C VPNMANAGER_FWD -i tun-vpnmanager -s 10.80.0.0/24 -j ACCEPT 2>/dev/null || iptables -A VPNMANAGER_FWD -i tun-vpnmanager -s 10.80.0.0/24 -j ACCEPT
iptables -C VPNMANAGER_FWD -o tun-vpnmanager -d 10.80.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A VPNMANAGER_FWD -o tun-vpnmanager -d 10.80.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C FORWARD -j VPNMANAGER_FWD 2>/dev/null || iptables -I FORWARD 1 -j VPNMANAGER_FWD
''', 0o700)
    write('/etc/systemd/system/vpnmanager-firewall.service', '''[Unit]
Description=VPN Manager IPv4 forwarding rules
After=network-pre.target ufw.service
Before=openvpn-server@vpnmanager.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/vpnmanager/firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'vpnmanager-firewall')
    run('systemctl', 'restart', 'vpnmanager-firewall')


def endpoint(value):
    if not value or len(value) > 253 or not re.fullmatch(r'[A-Za-z0-9.:-]+', value):
        raise ValueError('Enter a public IP address or DNS hostname, without a scheme or port.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if ':' in value or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in value.split('.')):
            raise ValueError('Invalid hostname.')
    return value


def export_client(config, output):
    host = endpoint(config['endpoint'])
    directory = Path('/etc/openvpn/server')
    ca = (directory / 'vpnmanager-ca.crt').read_text()
    key = (directory / 'vpnmanager-tls.key').read_text()
    write(output, f'''client
dev tun
proto tcp-client
remote {host} {config['openvpn_port']}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
auth-user-pass
auth-nocache
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verb 3
<ca>
{ca}</ca>
<tls-crypt>
{key}</tls-crypt>
''')
    print(f'Client profile written to {output}. It uses managed account credentials.')


def diagnostics(config):
    print('Service status:')
    for name, unit in {'ssh backend': 'vpnmanager-sshd', **SERVICES}.items():
        result = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
        print(f'  {name}: {result.stdout.strip()}')
    print('\nTCP listeners:')
    run('ss', '-ltnp')
    print('\nOnline sessions:')
    print(json.dumps(collect(), indent=2))
    print('\nCheck DNS A/AAAA records, TLS certificate, provider firewall and client protocol.')
    print('The server cannot override an ISP blocking its IP address or protocol.')
    print('For full-tunnel clients, test DNS and reduce client tun-mtu to 1400 if large transfers stall.')
    print('Account counts are sessions, not unique people; SSH and OpenVPN may count the same person twice.')


def choose(title, options):
    while True:
        print('\n' + title)
        for key, label, _ in options:
            print(f'  {key}. {label}')
        selected = input('Select an option: ').strip().lstrip('0') or '0'
        for key, _, action in options:
            if selected == key:
                return action
        print('Invalid option. Choose one of the listed numbers.')


def connections():
    while True:
        config = load()
        def setup(name):
            number = input(f'TCP port [{config[name + "_port"]}]: ').strip() or str(config[name + '_port'])
            if name == 'squid':
                values = input('Allowed client IPs/CIDRs (space separated; use actual ISP public IP ranges): ').split()
                config['squid_networks'] = [str(ipaddress.ip_network(value, strict=False)) for value in values]
            configure(name, config, number)
        def ssh():
            configure_ssh(config, port(input('Dedicated loopback SSH port [2222]: ') or '2222'))
        def stop():
            name = input('Service to disable (tunnel/tls/online/squid/openvpn): ').strip()
            if name not in SERVICES:
                raise ValueError('Unknown service.')
            run('systemctl', 'disable', '--now', SERVICES[name])
            config['enabled'] = [item for item in config['enabled'] if item != name]
            save(config)
        action = choose('Connection settings (menu 10)', [
            ('1', 'Configure dedicated SSH backend', ssh),
            ('2', 'Configure Squid proxy', lambda: setup('squid')),
            ('3', 'Configure TLS tunnel', lambda: setup('tls')),
            ('4', 'Configure OpenVPN TCP', lambda: setup('openvpn')),
            ('5', 'Configure HTTP / WebSocket tunnel', lambda: setup('tunnel')),
            ('6', 'Configure online status API', lambda: setup('online')),
            ('7', 'Disable a service', stop),
            ('8', 'Connection diagnostics', lambda: diagnostics(config)),
            ('0', 'Back', None)])
        if action is None:
            return
        try:
            action()
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(f'Error: {error}')


def user_menu():
    while True:
        def name():
            username = input('Username: ').strip()
            managed(username)
            return username
        def create():
            create_user(input('Username: ').strip(), int(input('Validity in days [30]: ') or '30'))
        def delete():
            username = name()
            if input(f'Type {username} to delete this account: ') != username:
                return
            disconnect(username)
            run('userdel', username)
        def renew():
            expiry(name(), int(input('Validity from today in days: ')))
        def lock():
            username = name()
            run('usermod', '-L', username)
            disconnect(username)
        action = choose('User management', [
            ('1', 'Create account / trial', create), ('2', 'List accounts', lambda: print('\n'.join(users()) or 'No managed users.')),
            ('3', 'Change password', lambda: password(name())), ('4', 'Renew expiry', renew),
            ('5', 'Lock and disconnect account', lock), ('6', 'Unlock account', lambda: run('usermod', '-U', name())),
            ('7', 'Delete account', delete), ('8', 'Show account expiry', lambda: run('chage', '-l', name())), ('0', 'Back', None)])
        if action is None:
            return
        try:
            action()
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(f'Error: {error}')


def make_backup():
    path = STATE / 'backups' / ('vpnmanager-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S') + '.tar.gz')
    # Configuration/PKI backup only. Do not copy the system shadow database.
    with tarfile.open(path, 'w:gz') as archive:
        archive.add('/etc/vpnmanager', arcname='vpnmanager')
        if Path('/etc/openvpn/server/vpnmanager.conf').exists():
            for item in Path('/etc/openvpn/server').glob('vpnmanager*'):
                archive.add(item, arcname='openvpn/' + item.name)
    path.chmod(0o600)
    print(f'Private configuration backup: {path}. Account passwords are not included.')


def restart_enabled(config):
    if Path('/etc/vpnmanager/sshd_config').exists():
        run('systemctl', 'restart', 'vpnmanager-sshd')
    for name in config['enabled']:
        run('systemctl', 'restart', SERVICES[name])


def menu():
    while True:
        config = load()
        def set_endpoint():
            config['endpoint'] = endpoint(input('Public server IP / hostname: ').strip())
            save(config)
        action = choose('VPN Manager', [
            ('1', 'User management', user_menu),
            ('2', 'Online sessions', lambda: print(json.dumps(collect(), indent=2))),
            ('3', 'Service status and diagnostics', lambda: diagnostics(config)),
            ('4', 'Restart enabled services', lambda: restart_enabled(config)),
            ('5', 'Back up private configuration', make_backup),
            ('6', 'Set public server endpoint', set_endpoint),
            ('7', 'Export OpenVPN client profile', lambda: export_client(config, input('Output path [/root/client.ovpn]: ') or '/root/client.ovpn')),
            ('8', 'Show listeners', lambda: run('ss', '-ltnp')),
            ('9', 'Show recent service logs', lambda: run('journalctl', '-n', '80', '--no-pager', *[arg for unit in SERVICES.values() for arg in ('-u', unit)])),
            ('10', 'Connection settings', connections), ('0', 'Exit', None)])
        if action is None:
            return
        try:
            action()
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(f'Error: {error}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='menu', choices=['menu', 'initialize', 'online', 'diagnostics', 'expire', 'serve-online', 'serve-tunnel'])
    args = parser.parse_args()
    root()
    config = load()
    if args.command == 'menu':
        menu()
    elif args.command == 'serve-online':
        online_serve(config['host'], config['online_port'])
    elif args.command == 'serve-tunnel':
        asyncio.run(tunnel_serve(config['host'], config['tunnel_port'], config['ssh_port'], config['openvpn_port']))
    elif args.command == 'online':
        print(json.dumps(collect(), indent=2))
    else:
        STATE.mkdir(parents=True, exist_ok=True)
        with (STATE / 'manager.lock').open('w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another management operation is running. Try again when it finishes.')
            {'initialize': initialize, 'menu': menu, 'diagnostics': lambda: diagnostics(config), 'expire': expire_portable}[args.command]()


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nClosed.')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
