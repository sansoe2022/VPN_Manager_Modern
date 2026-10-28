#!/usr/bin/env python3
"""Readable VPN Manager CLI for Ubuntu 20.04+ and Debian 12+."""
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
import accounts
import time
import signal
import dropbear_state
import profile_links
import shared_keys

from online import collect, serve as online_serve
from tunnel import serve as tunnel_serve

CONFIG = Path('/etc/vpnmanager/config.json')
STATE = Path('/var/lib/vpnmanager')
GROUP = 'vpnmanager'
DEFAULTS = {'host': '0.0.0.0', 'ssh_port': 22, 'tunnel_port': 80, 'tls_port': 443,
            'online_port': 81, 'online_app_limit': 2500, 'squid_port': 3128, 'openvpn_port': 1194,
            'endpoint': '', 'openvpn_key_source': 'shared', 'squid_networks': ['127.0.0.1/32'], 'enabled': []}
SERVICES = {'tunnel': 'vpnmanager-tunnel', 'tls': 'vpnmanager-tls',
            'online': 'vpnmanager-online', 'squid': 'squid',
            'openvpn': 'openvpn-server@vpnmanager', 'dropbear': 'vpnmanager-dropbear',
            'sslh': 'vpnmanager-sslh', 'badvpn': 'vpnmanager-badvpn'}


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
    if not Path('/etc/vpnmanager/banner').exists():
        write('/etc/vpnmanager/banner', '', 0o644)
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


def validate_password(value):
    if not value or any(char in value for char in ':\r\n\0'):
        raise ValueError('Use at least 1 character, without colons, NUL or newlines.')
    return value


def set_password(username, value):
    valid_user(username)
    validate_password(value)
    # Apply the requested policy only to this account, not the host PAM policy.
    run('chpasswd', '-c', 'SHA512', input=f'{username}:{value}\n')


def password(username):
    first = validate_password(getpass.getpass('New password: '))
    if first != getpass.getpass('Repeat password: '):
        raise ValueError('Passwords do not match.')
    set_password(username, first)


def expiry(username, days):
    if not 1 <= days <= 3650:
        raise ValueError('Validity must be between 1 and 3650 days.')
    date = dt.date.today() + dt.timedelta(days=days)
    run('chage', '-E', date.isoformat(), username)
    accounts.update(username, expires_at=None)
    print(f'{username} expires on {date} (server date).')


def create_user(username, days, secret=None, limit=1):
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
        if secret is None:
            password(username)
        else:
            set_password(username, secret)
        expiry(username, days)
        accounts.update(username, limit=limit)
    except BaseException:
        run('userdel', username)
        raise
    print('Account created. SSH clients must use forwarding / no-session mode.')


def disconnect(username):
    managed(username)
    result = subprocess.run(['pkill', '-TERM', '-u', username], check=False)
    if result.returncode not in (0, 1):
        raise ValueError('Unable to disconnect SSH sessions.')
    for owner, pid in dropbear_state.sessions():
        if owner == username:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
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
    # getent works on Python 3.8 through 3.13+, without the removed spwd module.
    records = accounts.load()
    for username in users():
        fields = capture('getent', 'shadow', username).split(':')
        if accounts.expired(records.get(username, {}), fields) or fields[1].startswith(('!', '*')):
            if not fields[1].startswith(('!', '*')):
                run('usermod', '-L', username)
            disconnect(username)
    profile_links.cleanup()


def enforce_limits():
    from collections import Counter
    counts = Counter(name for names in collect()['users'].values() for name in names)
    for username, record in accounts.load().items():
        if username in users() and counts[username] > record.get('limit', 1):
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


def configure_ssh(config, number, bind=None):
    bind = bind or config.get('ssh_bind', '127.0.0.1')
    ipaddress.ip_address(bind)
    if number == config['ssh_port'] and bind == config.get('ssh_bind', '127.0.0.1') and Path('/etc/vpnmanager/sshd_config').exists():
        run('systemctl', 'restart', 'vpnmanager-sshd')
        return
    free_port(number)
    Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
    run('ssh-keygen', '-A')
    text = f'''Port {number}
ListenAddress {bind}
Banner /etc/vpnmanager/banner
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
    config['ssh_bind'] = bind
    save(config)
    run('systemctl', 'enable', '--now', 'vpnmanager-sshd')
    run('systemctl', 'restart', 'vpnmanager-sshd')
    if 'tunnel' in config['enabled']:
        run('systemctl', 'restart', SERVICES['tunnel'])
    if 'squid' in config['enabled']:
        configure('squid', config, config['squid_port'])
    print(f'Dedicated SSH backend listens on {bind}:{number}; administrator SSH is unchanged.')


def squid_config(config):
    networks = [str(ipaddress.ip_network(value, strict=False)) for value in config['squid_networks']]
    if not networks:
        raise ValueError('At least one allowed client IP/CIDR is required.')
    hosts = []
    for value in config.get('squid_hosts', []):
        endpoint(value.lstrip('.'))
        hosts.append(value)
    host_acl = ('acl manager_hosts dstdomain ' + ' '.join(hosts) + '\n'
                + 'acl host_ports port 80 443\n'
                + 'http_access allow manager_clients host_ports manager_hosts\n') if hosts else ''
    return f'''http_port {config['squid_port']}
visible_hostname vpnmanager
acl manager_clients src {' '.join(networks)}
acl vpn_backend dst 127.0.0.1/32
acl vpn_ports port {config['ssh_port']} {config['openvpn_port']} {config['tunnel_port']}
http_access allow manager_clients vpn_ports vpn_backend
{host_acl}http_access deny all
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
        backend = config.get('tls_backend', 'tunnel')
        if backend not in ('ssh', 'tunnel', 'openvpn'):
            raise ValueError('Choose an SSH, OpenVPN or HTTP/WebSocket TLS backend.')
        if backend == 'ssh' and not Path('/etc/vpnmanager/sshd_config').exists():
            raise ValueError('Configure OpenSSH first.')
        if backend != 'ssh' and backend not in config['enabled']:
            raise ValueError('Enable the selected TLS backend first.')
        write('/etc/vpnmanager/stunnel.conf', f'''foreground = yes
pid =
cert = {cert}
sslVersionMin = TLSv1.2
[https-tunnel]
accept = {config['host']}:{number}
connect = 127.0.0.1:{config[backend + '_port']}
''')
    elif name == 'tunnel':
        enabled = config.get('proxy_backends', ['ssh', 'openvpn'])
        if not enabled or set(enabled) - {'ssh', 'openvpn'}:
            raise ValueError('Select SSH, OpenVPN or both proxy backends.')
        if 'ssh' in enabled and not Path('/etc/vpnmanager/sshd_config').exists():
            raise ValueError('Configure the SSH proxy backend first.')
        if 'openvpn' in enabled and not Path('/etc/openvpn/server/vpnmanager.conf').exists():
            raise ValueError('Configure the OpenVPN proxy backend first.')
    elif name == 'openvpn':
        setup_openvpn(config)
    save(config)
    start(name, config)
    if name in ('tunnel', 'openvpn') and 'squid' in config['enabled']:
        configure('squid', config, config['squid_port'])
    if name == 'tunnel' and 'tls' in config['enabled']:
        configure('tls', config, config['tls_port'])


def configure_proxy(config, number, backends):
    number = port(number)
    if not backends or set(backends) - {'ssh', 'openvpn'}:
        raise ValueError('Select SSH, OpenVPN or both proxy backends.')
    if 'tunnel' not in config['enabled'] or config['tunnel_port'] != number:
        free_port(number)
    if 'ssh' in backends:
        if not Path('/etc/vpnmanager/sshd_config').exists():
            configure_ssh(config, 2222, '127.0.0.1')
        run('systemctl', 'enable', '--now', 'vpnmanager-sshd')
    if 'openvpn' in backends:
        configure('openvpn', config, config['openvpn_port'])
    config['proxy_backends'] = list(backends)
    configure('tunnel', config, number)
    print('Proxy backends: ' + ', '.join(backends))
    print('Use /ssh for SSH and /openvpn for OpenVPN, or an allowed local CONNECT target.')


def openvpn_version():
    # OpenVPN 2.4 prints a valid version banner but exits with status 1.
    result = subprocess.run(['openvpn', '--version'], capture_output=True, text=True, check=False)
    match = re.search(r'^OpenVPN (\d+)\.(\d+)', result.stdout)
    if result.returncode not in (0, 1) or not match:
        raise ValueError('Cannot determine the installed OpenVPN version.')
    version = tuple(map(int, match.groups()))
    if version < (2, 4):
        raise ValueError('OpenVPN 2.4 or later is required.')
    return version


def openvpn_ciphers(version, shared=False):
    if shared:
        prefix = 'ncp-ciphers' if version < (2, 5) else 'data-ciphers'
        fallback = 'cipher AES-256-CBC' if version < (2, 5) else 'data-ciphers-fallback AES-256-CBC'
        return prefix + ' AES-256-GCM:AES-128-GCM:AES-256-CBC\n' + fallback
    # Ubuntu 20.04 ships OpenVPN 2.4, before data-ciphers was introduced.
    if version < (2, 5):
        return 'ncp-ciphers AES-256-GCM:AES-128-GCM'
    return 'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305'


def setup_openvpn(config):
    if not Path('/dev/net/tun').exists():
        raise ValueError('The host must provide /dev/net/tun for OpenVPN.')
    version = openvpn_version()
    directory = Path('/etc/openvpn/server')
    directory.mkdir(parents=True, exist_ok=True)
    mode = config.get('openvpn_key_source', 'shared')
    if mode not in ('shared', 'unique'):
        raise ValueError('OpenVPN key source must be shared or unique.')
    shared = mode == 'shared'
    if shared:
        shared_keys.install(sys.modules[__name__], directory)
    else:
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
            if version < (2, 5):
                run('openvpn', '--genkey', '--secret', str(key))
            else:
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
{'dh vpnmanager-dh.pem' if shared else 'dh none'}
{'tls-auth vpnmanager-tls.key 0' if shared else 'tls-crypt vpnmanager-tls.key'}
auth SHA256
tls-version-min 1.2
{openvpn_ciphers(version, shared)}
verify-client-cert none
username-as-common-name
duplicate-cn
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
    if ('BEGIN CERTIFICATE' not in ca or 'BEGIN OpenVPN Static key V1' not in key
            or 'PRIVATE KEY' in ca or 'PRIVATE KEY' in key):
        raise ValueError('The client CA/TLS authentication files are invalid or contain an unexpected private key.')
    server_config = (directory / 'vpnmanager.conf').read_text()
    shared = any(row.startswith('tls-auth ') for row in server_config.splitlines())
    transport = config.get('openvpn_client_transport', 'direct')
    if transport not in ('direct', 'proxy'):
        raise ValueError('Choose a direct or HTTP proxy client transport.')
    if transport == 'proxy' and 'openvpn' not in config.get('proxy_backends', []):
        raise ValueError('Enable the OpenVPN proxy backend in menu 10 -> 05 first.')
    remote = '127.0.0.1' if transport == 'proxy' else host
    proxy = f'http-proxy {host} {config["tunnel_port"]}\nhttp-proxy-option VERSION 1.1\n' if transport == 'proxy' else ''
    cipher_list = 'AES-256-GCM:AES-128-GCM' + (':AES-256-CBC' if shared else '')
    fallback = 'data-ciphers-fallback AES-256-CBC\ncipher AES-256-CBC\n' if shared else ''
    key_tag = 'tls-auth' if shared else 'tls-crypt'
    direction = 'key-direction 1\n' if shared else ''
    write(output, f'''client
dev tun
proto tcp-client
remote {remote} {config['openvpn_port']}
{proxy}resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
auth-user-pass
auth-nocache
tls-version-min 1.2
ignore-unknown-option data-ciphers ncp-ciphers data-ciphers-fallback
data-ciphers {cipher_list}
ncp-ciphers {cipher_list}
{fallback}auth SHA256
{direction}verb 3
<ca>
{ca}</ca>
<{key_tag}>
{key}</{key_tag}>
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


def clear_terminal():
    if sys.stdout.isatty():
        print('\033[2J\033[H', end='', flush=True)


def choose(title, options):
    while True:
        clear_terminal()
        print('\n' + title)
        print('=' * 47)
        for key, label, _ in options:
            print(f'  {key}. {label}')
        selected = input('Select an option: ').strip().lstrip('0') or '0'
        for key, label, action in options:
            if selected == key:
                clear_terminal()
                if action is not None:
                    print(title + ' - ' + label)
                    print('=' * 47)
                return action
        print('Invalid option. Choose one of the listed numbers.')


def connections():
    from classic import Classic
    Classic(sys.modules[__name__]).connections()


def restart_enabled(config):
    if Path('/etc/vpnmanager/sshd_config').exists():
        run('systemctl', 'restart', 'vpnmanager-sshd')
    for name in config['enabled']:
        run('systemctl', 'restart', SERVICES[name])


def menu():
    from classic import Classic
    Classic(sys.modules[__name__]).menu()


def main():
    os.environ['LC_ALL'] = 'C.UTF-8'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='menu', choices=['menu', 'initialize', 'online', 'diagnostics', 'expire', 'serve-online', 'serve-tunnel', 'enforce-limits', 'serve-bot', 'feature'])
    parser.add_argument('name', nargs='?', help='Feature name or bot role')
    args = parser.parse_args()
    root()
    config = load()
    if args.command == 'menu':
        menu()
    elif args.command == 'feature':
        from classic import Classic
        Classic(sys.modules[__name__]).feature(args.name)
    elif args.command == 'serve-bot':
        from telegram_bot import serve
        serve(sys.modules[__name__], args.name)
    elif args.command == 'enforce-limits':
        enforce_limits()
    elif args.command == 'serve-online':
        online_serve(config['host'], config['online_port'])
    elif args.command == 'serve-tunnel':
        asyncio.run(tunnel_serve(config['host'], config['tunnel_port'], config['ssh_port'], config['openvpn_port'], config.get('proxy_backends', ['ssh', 'openvpn'])))
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
