"""Run as root inside a disposable distro container, never on a production host."""
import getpass
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import online

real_run = manager.run


def run(*args, **kwargs):
    # Containers have no systemd PID 1. Test actual parsers, daemons and PAM;
    # systemd boot ordering is covered by systemd-analyze and a VM checklist.
    if args[0] in ('systemctl', 'sysctl'):
        return subprocess.CompletedProcess(args, 0, '')
    return real_run(*args, **kwargs)


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
        manager.configure('tls', config, 1443)
        tls = subprocess.Popen(['/usr/bin/stunnel', '/etc/vpnmanager/stunnel.conf'])
        processes.append(tls)
        time.sleep(0.2)
        assert tls.poll() is None, 'TLS listener failed to start'
        # Configuration generation only: containers do not provide a routed TUN.
        Path('/dev/net').mkdir(exist_ok=True)
        Path('/dev/net/tun').touch(exist_ok=True)
        manager.setup_openvpn(config)
        config['endpoint'] = 'vpn.example.com'
        manager.export_client(config, '/tmp/client.ovpn')
        exported = Path('/tmp/client.ovpn').read_text()
        assert 'PRIVATE KEY' not in exported
        assert '<ca>' in exported and 'auth-user-pass' in exported
        # PAM account expiry is enforced and the periodic job terminates sessions.
        subprocess.run(['chage', '-E', '2000-01-01', 'vpntest'], check=True)
        manager.expire_portable()
        client.wait(timeout=5)
        assert not online.collect()['ssh']
        print('PASS: SSH authentication/forwarding, online count, expiry, Squid CONNECT/deny, TLS startup, OpenVPN PKI/profile generation')
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
