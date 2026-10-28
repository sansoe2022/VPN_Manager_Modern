"""Real TLS/PAM/TUN handshakes; run only in a disposable NET_ADMIN container."""
import asyncio
import contextlib
import os
import ssl
import socket
import shutil
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import tunnel
import online

PROXY_PORT = 8880
SSH_PROXY_PORT = 2086
ADAPTER_PORT = 18081
SSH_ADAPTER_PORT = 18082

DOUBLE_HEADER = b'CONNECT / HTTP/1.1\r\nHost: dl.dir.freefiremobile.com\r\n\r\nCF-RAY / HTTP/1.1\r\nHost: vpn.example.com\r\nUpgrade: Mozilla/5.0\r\n\r\n'
GET_PATCH = b'GET http://help.twitter.com/ HTTP/1.1\r\nHost: help.twitter.com\r\nUser-Agent: Test-UA\r\n\r\nPATCH / HTTP/1.1\r\nHost: vpn.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'



async def from_ws(reader, writer):
    while True:
        first, size = await reader.readexactly(2)
        if size == 126:
            size = struct.unpack('!H', await reader.readexactly(2))[0]
        elif size == 127:
            size = struct.unpack('!Q', await reader.readexactly(8))[0]
        data = await reader.readexactly(size)
        if first & 15 == 8:
            return
        if first & 15 in (0, 1, 2):
            writer.write(data)
            await writer.drain()


async def to_ws(reader, writer):
    while True:
        data = await reader.read(32768)
        if not data:
            return
        mask = os.urandom(4)
        header = bytes((130, 128 | len(data))) if len(data) < 126 else b'\x82\xfe' + struct.pack('!H', len(data))
        writer.write(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(data)))
        await writer.drain()


async def adapter(reader, writer, mode):
    remote = None
    tasks = []
    try:
        context = ssl.create_default_context(cafile='/etc/vpnmanager/tls.crt') if mode == 'ssl' else None
        number = 443 if mode == 'ssl' else SSH_PROXY_PORT if mode in ('ssh','ssh-patch') else PROXY_PORT
        upstream, remote = await asyncio.open_connection('127.0.0.1', number, ssl=context,
            server_hostname='VPN-Manager' if context else None)
        if mode in ('get-patch', 'ssh-patch'):
            request = GET_PATCH
        elif mode in ('double-header', 'ssh'):
            request = DOUBLE_HEADER
        elif mode == 'legacy':
            request = b'GET /carrier-payload HTTP/1.1\r\nHost: example.com\r\nX-Real-Host: 0.0.0.0:1194\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
        elif mode == 'connect':
            request = b'CONNECT 127.0.0.1:1194 HTTP/1.1\r\nHost: localhost\r\n\r\n'
        else:
            request = b'GET /openvpn HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'
        if mode != 'ssl':
            remote.write(request)
            await remote.drain()
            response = await upstream.readuntil(b'\r\n\r\n')
            assert response.startswith(b'HTTP/1.1 200' if mode in ('connect', 'double-header', 'ssh') else b'HTTP/1.1 101'), response
        tasks = [asyncio.create_task(to_ws(reader, remote) if mode == 'websocket' else tunnel.relay(reader, remote)),
                 asyncio.create_task(from_ws(upstream, writer) if mode == 'websocket' else tunnel.relay(upstream, writer))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (remote, writer):
            if stream:
                stream.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(stream.wait_closed(), 2)


async def main():
    if os.geteuid() or not Path('/.dockerenv').exists():
        raise RuntimeError('Run inside a disposable root container with --cap-add NET_ADMIN.')
    shutil.copytree('/src/vpnmanager', '/usr/local/lib/vpnmanager', dirs_exist_ok=True)
    Path('/usr/local/lib/vpnmanager').chmod(0o755)
    for source in Path('/usr/local/lib/vpnmanager').glob('*.py'):
        source.chmod(0o644)
    manager.write('/usr/local/bin/vpnmanager', '#!/bin/sh\nexec python3 /usr/local/lib/vpnmanager/manager.py "$@"\n', 0o755)
    Path('/dev/net').mkdir(exist_ok=True)
    if not Path('/dev/net/tun').exists():
        os.mknod('/dev/net/tun', 0o20600, os.makedev(10, 200))
    Path('/run/openvpn-server').mkdir(exist_ok=True)
    real_run = manager.run
    def run(*args, **kwargs):
        if args[0] in ('systemctl', 'sysctl'):
            return subprocess.CompletedProcess(args, 0, '')
        return real_run(*args, **kwargs)
    def start(name, config):
        # Systemd is not PID 1 here; start the generated daemons below instead.
        config['enabled'] = sorted(set(config['enabled']) | {name})
        manager.save(config)
    with patch.object(manager, 'run', side_effect=run), patch.object(manager, 'start', side_effect=start):
        manager.initialize()
        config = manager.load()
        config['endpoint'] = '127.0.0.1'
        manager.write('/etc/vpnmanager/banner', '<h3>VPN test banner</h3>\n', 0o644)
        manager.create_user('vpnhandshake', 1, secret='1')
        manager.configure_proxy(config, PROXY_PORT, ['openvpn'])
        manager.configure_proxy(config, SSH_PROXY_PORT, ['ssh'])
        config['tls_backend'] = 'openvpn'
        manager.configure('tls', config, 443)
        manager.export_client(config, '/tmp/live.ovpn')
        manager.save(config)
    manager.write('/tmp/live-auth', 'vpnhandshake\n1\n')
    gate = subprocess.Popen(['python3', '/usr/local/lib/vpnmanager/admission.py', 'serve'])
    for _ in range(60):
        if Path('/run/vpnmanager-admission/gate.sock').exists():
            break
        await asyncio.sleep(.1)
    server = subprocess.Popen(['openvpn', '--cd', '/etc/openvpn/server', '--config', 'vpnmanager.conf', '--log', '/tmp/live-server.log'])
    # First activation persists the listeners before start() marks tunnel enabled.
    config['enabled'].remove('tunnel')
    manager.save(config)
    proxy_log = open('/tmp/live-proxy.log', 'w')
    proxy = subprocess.Popen(['python3', str(Path(manager.__file__)), 'serve-tunnel'], stdout=proxy_log, stderr=subprocess.STDOUT)
    for _ in range(60):
        await asyncio.sleep(.1)
        if manager.capture('ss','-H','-ltn','sport','=',str(PROXY_PORT)):
            break
        if proxy.poll() is not None:
            raise AssertionError('First proxy startup failed: '+Path('/tmp/live-proxy.log').read_text())
    else:
        raise AssertionError('First proxy listener did not start')
    config['enabled'].append('tunnel')
    manager.save(config)
    ssh_log = open('/tmp/live-ssh.log', 'w')
    sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', '/etc/vpnmanager/sshd_config'], stdout=ssh_log, stderr=subprocess.STDOUT)
    tls = subprocess.Popen(['/usr/bin/stunnel', '/etc/vpnmanager/stunnel.conf'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ssh_bridge = await asyncio.start_server(lambda r, w: adapter(r, w, 'ssh-patch'), '127.0.0.1', SSH_ADAPTER_PORT)
    ssh_client = None
    client = None
    try:
        await asyncio.sleep(1)
        ssh_client = subprocess.Popen(['sshpass', '-p', '1', 'ssh', '-N', '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null', '-p', str(SSH_ADAPTER_PORT), 'vpnhandshake@127.0.0.1'],
            stdout=ssh_log, stderr=subprocess.STDOUT)
        for _ in range(40):
            await asyncio.sleep(.1)
            if 'vpnhandshake' in online.collect()['users']['ssh']:
                print('PASS real SSH password authentication through WS 2086 and user absolute GET + PATCH payload', flush=True)
                break
        else:
            raise AssertionError('SSH WebSocket password login failed')
        for mode in ('direct', 'legacy', 'connect', 'websocket', 'http-proxy', 'double-header', 'get-patch', 'ssl'):
            bridge = None
            if mode not in ('direct', 'http-proxy'):
                bridge = await asyncio.start_server(lambda r, w: adapter(r, w, mode), '127.0.0.1', ADAPTER_PORT)
            log = Path('/tmp/live-client-' + mode + '.log')
            config['openvpn_client_transport'] = 'proxy' if mode == 'http-proxy' else 'custom-app' if mode == 'legacy' else 'direct'
            manager.export_client(config, '/tmp/live.ovpn')
            profile = Path('/tmp/live.ovpn').read_text()
            if bridge:
                port = PROXY_PORT if mode == 'legacy' else 1194
                profile = profile.replace(f'remote 127.0.0.1 {port}', f'remote 127.0.0.1 {ADAPTER_PORT}')
            manager.write('/tmp/live-' + mode + '.ovpn', profile)
            client = subprocess.Popen(['openvpn', '--config', '/tmp/live-' + mode + '.ovpn', '--auth-user-pass', '/tmp/live-auth', '--route-noexec', '--ifconfig-noexec', '--management', '/tmp/live-echo', 'unix', '--log', str(log)])
            try:
                for _ in range(120):
                    await asyncio.sleep(.25)
                    text = log.read_text() if log.exists() else ''
                    if 'Initialization Sequence Completed' in text:
                        with socket.socket(socket.AF_UNIX) as control:
                            control.settimeout(3)
                            control.connect('/tmp/live-echo')
                            control.sendall(b'echo all\n')
                            messages = b''
                            while b'END' not in messages:
                                messages += control.recv(4096)
                            assert b'VPN test banner' in messages, 'OpenVPN banner ECHO missing'
                        print('PASS real OpenVPN TLS/PAM/TUN and banner ECHO: ' + mode, flush=True)
                        assert ssh_client.poll() is None, 'SSH WS session lost during OpenVPN connection'
                        break
                    if client.poll() is not None:
                        raise AssertionError('OpenVPN client exited: ' + mode)
                else:
                    raise AssertionError('OpenVPN handshake timed out: ' + mode)
            finally:
                if client.poll() is None:
                    client.terminate()
                    client.wait(timeout=5)
                if bridge:
                    bridge.close()
                    await bridge.wait_closed()
                await asyncio.sleep(.2)
    except BaseException:
        for log in Path('/tmp').glob('live-*.log'):
            print(log.name + '\n' + log.read_text())
        raise
    finally:
        ssh_bridge.close()
        for process in (ssh_client, tls, sshd, proxy, server, gate):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        await asyncio.wait_for(ssh_bridge.wait_closed(), 5)
        proxy_log.close()
        ssh_log.close()


if __name__ == '__main__':
    asyncio.run(main())
