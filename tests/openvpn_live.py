"""Real TLS/PAM/TUN handshakes; run only in a disposable NET_ADMIN container."""
import asyncio
import contextlib
import os
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import tunnel

PROXY_PORT = 18080
ADAPTER_PORT = 18081


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
        upstream, remote = await asyncio.open_connection('127.0.0.1', PROXY_PORT)
        if mode == 'legacy':
            request = b'GET /carrier-payload HTTP/1.1\r\nHost: example.com\r\nX-Real-Host: 0.0.0.0:1194\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
        elif mode == 'connect':
            request = b'CONNECT 127.0.0.1:1194 HTTP/1.1\r\nHost: localhost\r\n\r\n'
        else:
            request = b'GET /openvpn HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'
        remote.write(request)
        await remote.drain()
        response = await upstream.readuntil(b'\r\n\r\n')
        assert response.startswith(b'HTTP/1.1 200' if mode == 'connect' else b'HTTP/1.1 101'), response
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
                with contextlib.suppress(OSError):
                    await stream.wait_closed()


async def main():
    if os.geteuid() or not Path('/.dockerenv').exists():
        raise RuntimeError('Run inside a disposable root container with --cap-add NET_ADMIN.')
    Path('/dev/net').mkdir(exist_ok=True)
    if not Path('/dev/net/tun').exists():
        os.mknod('/dev/net/tun', 0o20600, os.makedev(10, 200))
    Path('/run/openvpn-server').mkdir(exist_ok=True)
    real_run = manager.run
    def run(*args, **kwargs):
        if args[0] in ('systemctl', 'sysctl'):
            return subprocess.CompletedProcess(args, 0, '')
        return real_run(*args, **kwargs)
    with patch.object(manager, 'run', side_effect=run):
        manager.initialize()
        config = manager.load()
        config.update(endpoint='127.0.0.1', tunnel_port=PROXY_PORT, proxy_backends=['ssh', 'openvpn'], enabled=['tunnel', 'openvpn'])
        manager.create_user('vpnhandshake', 1, secret='1')
        manager.setup_openvpn(config)
        manager.export_client(config, '/tmp/live.ovpn')
        manager.save(config)
    manager.write('/tmp/live-auth', 'vpnhandshake\n1\n')
    server = subprocess.Popen(['openvpn', '--cd', '/etc/openvpn/server', '--config', 'vpnmanager.conf', '--log', '/tmp/live-server.log'])
    proxy = await asyncio.start_server(lambda r, w: tunnel.handle(r, w, tunnel.routes(2222, 1194, ['ssh', 'openvpn'])), '127.0.0.1', PROXY_PORT)
    client = None
    try:
        await asyncio.sleep(1)
        for mode in ('direct', 'legacy', 'connect', 'websocket', 'http-proxy'):
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
            client = subprocess.Popen(['openvpn', '--config', '/tmp/live-' + mode + '.ovpn', '--auth-user-pass', '/tmp/live-auth', '--route-noexec', '--ifconfig-noexec', '--log', str(log)])
            try:
                for _ in range(120):
                    await asyncio.sleep(.25)
                    text = log.read_text() if log.exists() else ''
                    if 'Initialization Sequence Completed' in text:
                        print('PASS real OpenVPN TLS/PAM/TUN: ' + mode, flush=True)
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
        proxy.close()
        await proxy.wait_closed()
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=5)


if __name__ == '__main__':
    asyncio.run(main())
