"""Run as root inside a disposable distro container, never on a production host."""
import getpass
import hashlib
import threading
from urllib.request import urlopen
from urllib.parse import urlsplit
from urllib.error import HTTPError
import os
from pathlib import Path
import socket
import ssl
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import extras
import accounts
import private_backup
import profile_links
import online

subprocess.run(['python3', '/src/tests/bootstrap_smoke.py'], check=True)

real_run = manager.run


def run(*args, **kwargs):
    # Containers have no systemd PID 1. Test actual parsers, daemons and PAM;
    # systemd boot ordering is covered by systemd-analyze and a VM checklist.
    if args[0] in ('systemctl', 'sysctl'):
        return subprocess.CompletedProcess(args, 0, '')
    return real_run(*args, **kwargs)


def forwarded_port(number):
    deadline = time.monotonic() + 5
    while True:
        try:
            return socket.create_connection(('127.0.0.1', number), timeout=3)
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.05)


with patch.object(manager, 'run', side_effect=run):
    shutil.copytree('/src/vpnmanager', '/usr/local/lib/vpnmanager', dirs_exist_ok=True)
    Path('/usr/local/bin/vpnmanager').write_text('#!/bin/sh\nexec python3 /usr/local/lib/vpnmanager/manager.py "$@"\n')
    Path('/usr/local/bin/vpnmanager').chmod(0o755)
    manager.initialize()
    subprocess.run(['systemd-analyze', 'verify', *map(str, Path('/etc/systemd/system').glob('vpnmanager*'))], check=True)
    config = manager.load()
    manager.configure_ssh(config, 2222)
    Path('/run/sshd').mkdir(exist_ok=True)
    sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', '/etc/vpnmanager/sshd_config'])
    processes = [sshd]
    try:
        with patch.object(manager.getpass, 'getpass', return_value='Test-password-47'):
            manager.create_user('vpntest', 7)
        manager.create_user('a', 1, secret='1')
        assert accounts.verify_password('a', '1')
        short = subprocess.Popen(['sshpass', '-p', '1', 'ssh', '-N', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-p', '2222', 'a@127.0.0.1'])
        processes.append(short)
        for _ in range(40):
            time.sleep(0.1)
            if 'a' in online.collect()['users']['ssh']:
                break
        else:
            raise AssertionError('Single-character account/password login failed')
        manager.disconnect('a')
        short.wait(timeout=5)
        # Real password authentication with the configured no-shell account.
        client = subprocess.Popen(['sshpass', '-p', 'Test-password-47', 'ssh', '-N',
                                   '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                                   '-o', 'ExitOnForwardFailure=yes', '-L', '127.0.0.1:23456:127.0.0.1:2222',
                                   '-p', '2222', 'vpntest@127.0.0.1'])
        processes.append(client)
        for _ in range(40):
            time.sleep(0.1)
            if online.collect()['ssh'] >= 1:
                break
        else:
            subprocess.run(['ps', '-eo', 'user,pid,args'], check=True)
            raise AssertionError('Authenticated SSH session was not counted')
        with socket.create_connection(('127.0.0.1', 23456), timeout=3) as forwarded:
            assert forwarded.recv(100).startswith(b'SSH-2.0-')
        assert accounts.verify_password('vpntest', 'Test-password-47')
        assert not accounts.verify_password('vpntest', 'wrong-password')
        # Extra services are preinstalled in the disposable test image.
        with patch.object(extras, 'package'):
            extras.dropbear(manager, config, 2209)
        drop = subprocess.Popen(['python3', '/src/vpnmanager/dropbear_runner.py', '2209'])
        processes.append(drop)
        time.sleep(0.2)
        drop_client = subprocess.Popen(['sshpass', '-p', 'Test-password-47', 'ssh', '-N',
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ExitOnForwardFailure=yes', '-L', '127.0.0.1:23457:127.0.0.1:2222', '-p', '2209', 'vpntest@127.0.0.1'])
        processes.append(drop_client)
        for _ in range(40):
            time.sleep(0.1)
            if online.collect()['dropbear'] >= 1:
                break
        else:
            subprocess.run(['ps', '-eo', 'user,pid,comm,args'], check=True)
            raise AssertionError('Authenticated Dropbear session was not counted')
        with forwarded_port(23457) as forwarded:
            assert forwarded.recv(100).startswith(b'SSH-2.0-')
        # Squid parses and actually forwards CONNECT to an allowed local SSH port.
        config['squid_networks'] = ['127.0.0.1/32']
        manager.configure('squid', config, 3128)
        squid = subprocess.Popen(['squid', '-N', '-f', '/etc/squid/squid.conf'])
        processes.append(squid)
        for _ in range(40):
            try:
                proxy = socket.create_connection(('127.0.0.1', 3128), timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError('Squid did not start')
        with proxy:
            proxy.sendall(b'CONNECT 127.0.0.1:2222 HTTP/1.1\r\nHost: 127.0.0.1:2222\r\n\r\n')
            response = proxy.recv(4096)
            assert b'200 Connection established' in response, response
            if b'SSH-2.0-' not in response:
                assert b'SSH-2.0-' in proxy.recv(4096)
        with socket.create_connection(('127.0.0.1', 3128), timeout=3) as denied:
            denied.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n')
            assert b'403' in denied.recv(4096)
        # Validate TLS configuration with a real daemon startup.
        config['enabled'] = ['tunnel']
        config['tls_backend'] = 'ssh'
        manager.configure('tls', config, 1443)
        tls = subprocess.Popen(['/usr/bin/stunnel', '/etc/vpnmanager/stunnel.conf'])
        processes.append(tls)
        time.sleep(0.2)
        assert tls.poll() is None, 'TLS listener failed to start'
        context = ssl.create_default_context(cafile='/etc/vpnmanager/tls.crt')
        with socket.create_connection(('127.0.0.1', 1443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname='VPN-Manager') as secured:
                assert secured.recv(100).startswith(b'SSH-2.0-')
        # SSLH must accept the distribution CLI and route an SSH handshake.
        with patch.object(extras, 'package'):
            extras.sslh(manager, config, 1444)
        unit = Path('/etc/systemd/system/vpnmanager-sslh.service').read_text()
        command = next(row.split('=', 1)[1] for row in unit.splitlines() if row.startswith('ExecStart='))
        import shlex
        multiplexer = subprocess.Popen(shlex.split(command))
        processes.append(multiplexer)
        time.sleep(0.2)
        assert multiplexer.poll() is None, 'SSLH failed to start'
        with socket.create_connection(('127.0.0.1', 1444), timeout=5) as multiplexed:
            multiplexed.sendall(b'SSH-2.0-TestClient\r\n')
            assert multiplexed.recv(100).startswith(b'SSH-2.0-')
        # Configuration generation only: containers do not provide a routed TUN.
        Path('/dev/net').mkdir(exist_ok=True)
        Path('/dev/net/tun').touch(exist_ok=True)
        manager.setup_openvpn(config)
        key_files = [Path('/etc/openvpn/server') / name for name in ('vpnmanager-ca.crt', 'vpnmanager-server.crt', 'vpnmanager-server.key', 'vpnmanager-dh.pem', 'vpnmanager-tls.key')]
        original_keys = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in key_files}
        manager.setup_openvpn(config)
        assert {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in key_files} == original_keys
        config['endpoint'] = 'vpn.example.com'
        manager.export_client(config, '/tmp/client.ovpn')
        exported = Path('/tmp/client.ovpn').read_text()
        assert 'PRIVATE KEY' not in exported
        assert '<ca>' in exported and 'auth-user-pass' in exported
        assert '<tls-auth>' in exported and 'key-direction 1' in exported
        # Ask the installed OpenVPN to parse both generated configurations.
        # This rejects version-incompatible options without needing a TUN device.
        subprocess.run(['openvpn', '--cd', '/etc/openvpn/server', '--config', 'vpnmanager.conf', '--show-ciphers'], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['openvpn', '--config', '/tmp/client.ovpn', '--show-ciphers'], check=True, stdout=subprocess.DEVNULL)
        # An actual HTTP download serves a valid client profile, never a private key.
        config['proxy_backends'] = ['ssh', 'openvpn']
        config['enabled'] = sorted(set(config['enabled']) | {'tunnel'})
        config['openvpn_client_transport'] = 'proxy'
        manager.export_client(config, '/tmp/proxy-client.ovpn')
        subprocess.run(['openvpn', '--config', '/tmp/proxy-client.ovpn', '--show-ciphers'], check=True, stdout=subprocess.DEVNULL)
        assert 'http-proxy vpn.example.com 80' in Path('/tmp/proxy-client.ovpn').read_text()
        url, expires = profile_links.create(manager, config, 60)
        route = urlsplit(url).path
        server = online.ThreadingHTTPServer(('127.0.0.1', 0), online.Handler)
        web = threading.Thread(target=server.serve_forever, daemon=True)
        web.start()
        try:
            with urlopen(f'http://127.0.0.1:{server.server_port}' + route) as response:
                downloaded = response.read().decode()
                assert 'PRIVATE KEY' not in downloaded and '<tls-auth>' in downloaded
                assert 'attachment' in response.headers['Content-Disposition']
            assert profile_links.read(route, now=expires) is None
            profile_links.cleanup(force=True)
        finally:
            server.shutdown()
            server.server_close()
            web.join()
        # Back up / restore only managed users; leave administrator shadow untouched.
        root_before = manager.capture('getent', 'shadow', 'root')
        snapshot = private_backup.create(manager)
        accounts.update('vpntest', limit=77)
        for path in key_files:
            manager.write(path, 'replacement to simulate a different server state')
        private_backup.restore(manager, snapshot, activate=False)
        assert accounts.load()['vpntest']['limit'] == 1
        assert {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in key_files} == original_keys
        assert manager.capture('getent', 'shadow', 'root') == root_before
        # PAM account expiry is enforced and the periodic job terminates sessions.
        subprocess.run(['chage', '-E', '2000-01-01', 'vpntest'], check=True)
        manager.expire_portable()
        client.wait(timeout=5)
        drop_client.wait(timeout=5)
        assert not online.collect()['ssh'] and not online.collect()['dropbear']
        print('PASS: SSH/Dropbear authentication/forwarding, online count, expiry, Squid CONNECT/deny, TLS startup, SSLH routing, password verification, OpenVPN PKI/profile generation')
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
