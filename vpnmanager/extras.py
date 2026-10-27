"""Source-based service setup for the original SSHPlus connection menu."""
from pathlib import Path
import ipaddress
import re
import shutil
import subprocess
import tempfile

BADVPN_TAG = '1.999.130'
BADVPN_COMMIT = '752c6b492bc6866e8af8313a6e348d5e0370fe1f'


def package(m, *names):
    m.run('apt-get', '-o', 'Acquire::Retries=3', 'update')
    m.run('apt-get', '-o', 'Acquire::Retries=3', 'install', '-y', '--no-install-recommends', *names)


def activate(m, name, command, config, extra='ReadWritePaths=/run'):
    m.service_unit('vpnmanager-' + name, command, extra)
    m.start(name, config)


def dropbear(m, config, number):
    m.free_port(number) if number != config.get('dropbear_port') or 'dropbear' not in config['enabled'] else None
    package(m, 'dropbear-bin')
    # Dropbear validates the account shell against /etc/shells, even for -N.
    # nologin still prevents interactive sessions.
    shells = Path('/etc/shells')
    if '/usr/sbin/nologin' not in shells.read_text().splitlines():
        m.backup(shells)
        m.write(shells, shells.read_text().rstrip() + '\n/usr/sbin/nologin\n', 0o644)
    Path('/etc/dropbear').mkdir(exist_ok=True)
    # RSA and ECDSA work on Ubuntu 20.04's older Dropbear too.
    for algorithm in ('rsa', 'ecdsa'):
        key = Path('/etc/dropbear') / ('dropbear_' + algorithm + '_host_key')
        if not key.exists():
            m.run('dropbearkey', '-t', algorithm, '-f', str(key))
    config['dropbear_port'] = number
    m.save(config)
    activate(m, 'dropbear', f'/usr/bin/python3 -B /usr/local/lib/vpnmanager/dropbear_runner.py {number}', config, 'ReadWritePaths=/run /var/lib/vpnmanager')


def sslh(m, config, number):
    m.free_port(number) if number != config.get('sslh_port') or 'sslh' not in config['enabled'] else None
    status = subprocess.run(['dpkg-query', '-W', '-f=${Status}', 'sslh'], capture_output=True, text=True)
    was_installed = status.returncode == 0 and status.stdout.strip() == 'install ok installed'
    package(m, 'sslh')
    if not was_installed:
        # The package can start a default listener during installation.
        m.run('systemctl', 'disable', '--now', 'sslh')
        m.free_port(number)
    # No shell parsing: all ports are validated integers.
    config['sslh_port'] = number
    m.save(config)
    command = (f'/usr/sbin/sslh --foreground --user sslh --listen 0.0.0.0:{number}'
               f' --ssh 127.0.0.1:{config["ssh_port"]}'
               f' --tls 127.0.0.1:{config["tls_port"]}'
               f' --http 127.0.0.1:{config["tunnel_port"]}'
               f' --openvpn 127.0.0.1:{config["openvpn_port"]}')
    activate(m, 'sslh', command, config)


def badvpn(m, config, number, binary=None):
    binary = Path(binary or '/usr/local/bin/badvpn-udpgw')
    if number != config.get('badvpn_port') or 'badvpn' not in config['enabled']:
        if hasattr(m, 'free_port'):
            m.free_port(number)
    if not binary.exists():
        package(m, 'build-essential', 'cmake', 'git')
        with tempfile.TemporaryDirectory(prefix='vpnmanager-badvpn-') as temp:
            source = Path(temp) / 'source'
            m.run('git', 'clone', '--branch', BADVPN_TAG, '--depth', '1', 'https://github.com/ambrop72/badvpn.git', str(source))
            if m.capture('git', '-C', str(source), 'rev-parse', 'HEAD') != BADVPN_COMMIT:
                raise ValueError('The BadVPN source revision does not match the reviewed release.')
            m.run('cmake', '-S', str(source), '-B', str(source / 'build'), '-DBUILD_NOTHING_BY_DEFAULT=1', '-DBUILD_UDPGW=1', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5')
            m.run('cmake', '--build', str(source / 'build'), '--parallel', '2')
            shutil.copy2(source / 'build/udpgw/badvpn-udpgw', binary)
            binary.chmod(0o755)
    config['badvpn_port'] = number
    m.save(config)
    activate(m, 'badvpn', f'{binary} --listen-addr 127.0.0.1:{number} --max-clients 250 --max-connections-for-client 8', config)


def limiter(m, enabled):
    m.write('/etc/systemd/system/vpnmanager-limiter.service', '''[Unit]
Description=Enforce SSHPlus per-account session limits
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnmanager enforce-limits
''', 0o644)
    m.write('/etc/systemd/system/vpnmanager-limiter.timer', '''[Unit]
Description=Check SSHPlus session limits every 15 seconds
[Timer]
OnBootSec=15s
OnUnitActiveSec=15s
[Install]
WantedBy=timers.target
''', 0o644)
    m.run('systemctl', 'daemon-reload')
    m.run('systemctl', 'enable' if enabled else 'disable', '--now', 'vpnmanager-limiter.timer')


def torrent(m, enabled):
    # Restrict only this feature's chains; preserve all administrator rules.
    script = '''#!/usr/bin/env bash
set -euo pipefail
for hook in OUTPUT FORWARD; do
  chain="VPNMANAGER_TOR_${hook}"
  iptables -N "$chain" 2>/dev/null || true
  iptables -F "$chain"
  for protocol in tcp udp; do
    iptables -A "$chain" -p "$protocol" --dport 6881:6889 -j REJECT
  done
  iptables -A "$chain" -m string --algo bm --string 'BitTorrent protocol' -j REJECT
  iptables -C "$hook" -j "$chain" 2>/dev/null || iptables -I "$hook" 1 -j "$chain"
done
'''
    m.write('/usr/local/lib/vpnmanager/torrent.sh', script, 0o700)
    m.write('/etc/systemd/system/vpnmanager-torrent.service', '''[Unit]
Description=SSHPlus BitTorrent filtering rules
After=network-pre.target ufw.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/vpnmanager/torrent.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''', 0o644)
    m.run('systemctl', 'daemon-reload')
    if enabled:
        m.run('systemctl', 'enable', '--now', 'vpnmanager-torrent')
    else:
        m.run('systemctl', 'disable', '--now', 'vpnmanager-torrent')
        for hook in ('OUTPUT', 'FORWARD'):
            chain = 'VPNMANAGER_TOR_' + hook
            for args in (('-D', hook, '-j', chain), ('-F', chain), ('-X', chain)):
                result = subprocess.run(['iptables', *args], capture_output=True, text=True)
                if result.returncode and 'No chain/target/match' not in result.stderr and 'Bad rule' not in result.stderr:
                    raise ValueError('Unable to remove torrent rule: ' + result.stderr.strip())
    print('Torrent filtering enabled.' if enabled else 'Torrent filtering disabled.')
    if enabled:
        print('Port/signature filtering cannot identify every encrypted BitTorrent connection.')


def swap(m, size):
    if not 0 <= size <= 32:
        raise ValueError('Choose 1-32 GiB, or 0 to disable this swap file.')
    path = Path('/var/lib/vpnmanager/swapfile')
    fstab = Path('/etc/fstab')
    m.backup(fstab)
    rows = [row for row in fstab.read_text().splitlines() if not row.startswith(str(path) + ' ')]
    active = any(row.split()[0] == str(path) for row in Path('/proc/swaps').read_text().splitlines()[1:])
    if active:
        m.run('swapoff', str(path))
    if size == 0:
        path.unlink(missing_ok=True)
    else:
        if not 1 <= size <= 32:
            raise ValueError('Choose 1-32 GiB, or 0 to disable this swap file.')
        if shutil.disk_usage(path.parent).free + (path.stat().st_size if path.exists() else 0) < (size + 1) * 1024 ** 3:
            raise ValueError('Not enough free space; leave at least 1 GiB free.')
        if path.exists():
            path.unlink()
        # Real allocation avoids sparse-file failures on common cloud filesystems.
        m.run('dd', 'if=/dev/zero', 'of=' + str(path), 'bs=1M', 'count=' + str(size * 1024), 'status=progress')
        path.chmod(0o600)
        m.run('mkswap', str(path))
        m.run('swapon', str(path))
        rows.append(str(path) + ' none swap sw 0 0')
    m.write(fstab, '\n'.join(rows) + '\n', 0o644)
    m.run('free', '-h')
