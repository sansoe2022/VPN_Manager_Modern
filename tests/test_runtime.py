import asyncio
from types import SimpleNamespace
import base64
import json
from pathlib import Path
import struct
import sys
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import online
import tunnel


class Counts(unittest.TestCase):
    def test_authenticated_ssh_only(self):
        sample = '''sshd: /usr/sbin/sshd -D [listener]
sshd: root [priv]
sshd: user [priv]
sshd: user@notty
sshd: user@pts/0
sshd-session: other@notty
sshd-session: newer
sshd-auth: unknown [net]
'''
        self.assertEqual(online.ssh_sessions(sample), ['user', 'user', 'other', 'newer'])

    def test_openvpn_versions(self):
        for delimiter in (',', '\t'):
            text = '\n'.join(delimiter.join(row) for row in [
                ['HEADER', 'CLIENT_LIST', 'Common Name'],
                ['CLIENT_LIST', 'alice', '1.2.3.4:999'],
                ['ROUTING_TABLE', '10.80.0.2', 'alice'],
                ['GLOBAL_STATS', 'Max bcast/mcast queue length', '0']])
            self.assertEqual(online.openvpn_sessions(text), ['alice'])
        self.assertEqual(online.openvpn_sessions(''), [])

    def test_proxy_acl_and_validation(self):
        config = {**manager.DEFAULTS, 'squid_networks': ['192.0.2.5/24']}
        rendered = manager.squid_config(config)
        self.assertIn('192.0.2.0/24', rendered)
        self.assertIn('http_access deny all', rendered)
        with self.assertRaises(ValueError):
            manager.squid_config({**config, 'squid_networks': ['anything\nhttp_access allow all']})
        for value in ['a\nremote evil', 'http://example.com', 'x;reboot', 'a:443']:
            with self.assertRaises(ValueError):
                manager.endpoint(value)

    def test_count_excludes_administrator_sessions(self):
        with patch.object(online.subprocess, 'run', return_value=SimpleNamespace(stdout='sshd: root@pts/0\nsshd-session: alice\nsshd: bob@notty')), \
             patch.object(online.grp, 'getgrnam', return_value=SimpleNamespace(gr_mem=['alice'], gr_gid=999)), \
             patch.object(online.pwd, 'getpwall', return_value=[]), \
             patch.object(online, 'STATUS_PATHS', ()):
            result = online.collect()
            self.assertEqual(result['total'], 1)
            self.assertEqual(result['users']['ssh'], ['alice'])

    def test_openvpn_distribution_versions(self):
        for banner, expected in [('OpenVPN 2.4.7 x86_64-linux-gnu', (2, 4)),
                                 ('OpenVPN 2.6.14 x86_64-pc-linux-gnu', (2, 6))]:
            with patch.object(manager.subprocess, 'run', return_value=SimpleNamespace(stdout=banner, returncode=1 if expected == (2, 4) else 0)):
                self.assertEqual(manager.openvpn_version(), expected)
        self.assertEqual(manager.openvpn_ciphers((2, 4)), 'ncp-ciphers AES-256-GCM:AES-128-GCM')
        self.assertTrue(manager.openvpn_ciphers((2, 5)).startswith('data-ciphers '))
        for banner in ('OpenVPN 2.3.18', 'unexpected output'):
            with patch.object(manager.subprocess, 'run', return_value=SimpleNamespace(stdout=banner, returncode=1)):
                with self.assertRaises(ValueError):
                    manager.openvpn_version()

    def test_api_legacy_schema(self):
        server = online.ThreadingHTTPServer(('127.0.0.1', 0), online.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with patch.object(online, 'collect', return_value={'total': 7}):
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                with urlopen(base + '/server/online_app') as response:
                    self.assertEqual(json.load(response), {'onlines': '7', 'limite': '2500'})
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                with urlopen(base + '/server/online') as response:
                    self.assertEqual(response.read(), b'7')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


class Tunnel(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.handlers = set()
        async def echo(reader, writer):
            try:
                while data := await reader.read(65535):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        self.echo = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.backend = self.echo.sockets[0].getsockname()[1]
        async def handle(reader, writer):
            task = asyncio.current_task()
            self.handlers.add(task)
            try:
                await tunnel.handle(reader, writer, {'/': self.backend, '/ssh': self.backend})
            finally:
                self.handlers.discard(task)
        self.server = await asyncio.start_server(handle, '127.0.0.1', 0)

    async def asyncTearDown(self):
        self.server.close()
        self.echo.close()
        await self.server.wait_closed()
        await self.echo.wait_closed()
        for task in list(self.handlers):
            task.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)

    async def connect(self):
        return await asyncio.open_connection('127.0.0.1', self.server.sockets[0].getsockname()[1])

    async def test_fragmented_headers_and_pipelined_binary(self):
        reader, writer = await self.connect()
        writer.write(b'GET /ssh HTTP/1.1\r\nHo')
        await writer.drain()
        await asyncio.sleep(0.01)
        data = bytes(range(256)) * 512
        writer.write(b'st: example.com\r\n\r\n' + data)
        await writer.drain()
        self.assertIn(b'101 Switching', await reader.readuntil(b'\r\n\r\n'))
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 5), data)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')

    async def test_rfc_websocket(self):
        reader, writer = await self.connect()
        writer.write(b'GET /ssh HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
        await writer.drain()
        self.assertIn(b's3pPLMBiTxaQ9kYGzzhZRbK+xOo=', await reader.readuntil(b'\r\n\r\n'))
        data = bytes(range(256)) * 128
        mask = b'1234'
        writer.write(b'\x82\xfe' + struct.pack('!H', len(data)) + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(data)))
        await writer.drain()
        received = b''
        while len(received) < len(data):
            first, size = await reader.readexactly(2)
            self.assertEqual(first, 130)
            if size == 126:
                size = struct.unpack('!H', await reader.readexactly(2))[0]
            received += await reader.readexactly(size)
        self.assertEqual(received, data)
        writer.close()
        await writer.wait_closed()

    async def test_user_double_header_payload_is_not_forwarded_as_vpn_data(self):
        for split in (False, True):
            reader, writer = await self.connect()
            first = b'CONNECT / HTTP/1.1\r\nHost: dl.dir.freefiremobile.com\r\n\r\n'
            second = b'CF-RAY / HTTP/1.1\r\nHost: vpn.example.com\r\nUpgrade: Mozilla/5.0\r\n\r\n'
            data = b'\x00\x14\x38\x00\xffVPN binary bytes'
            writer.write(first + (b'' if split else second + data))
            await writer.drain()
            self.assertIn(b'200 Connection Established', await reader.readuntil(b'\r\n\r\n'))
            if split:
                for part in (second[:2], second[2:20], second[20:] + data):
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(.01)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 2), data)
            writer.close()
            await writer.wait_closed()

    async def test_absolute_get_patch_payload_is_stripped_even_when_fragmented(self):
        first = b'GET http://help.twitter.com/ HTTP/1.1\r\nHost: help.twitter.com\r\nUser-Agent: Test-UA\r\n\r\n'
        second = b'PATCH / HTTP/1.1\r\nHost: vpn.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'
        for split in (False, True):
            reader, writer = await self.connect()
            data = b'\x00\xffVPN bytes including GET / HTTP/1.1\r\n\r\n'
            writer.write(first + (b'' if split else second + data))
            await writer.drain()
            self.assertIn(b'101 Switching', await reader.readuntil(b'\r\n\r\n'))
            if split:
                for part in (second[:1],second[1:4],second[4:30],second[30:] + data):
                    writer.write(part); await writer.drain(); await asyncio.sleep(.01)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)),2), data)
            writer.close(); await writer.wait_closed()

    async def test_raw_http_methods_support_carrier_prefaces(self):
        for method in ('GET','POST','PATCH','PUT','HEAD','OPTIONS','DELETE'):
            reader, writer = await self.connect()
            data = b'SSH-2.0-native-bytes\r\n'
            writer.write((method+' / HTTP/1.1\r\nHost: carrier.example\r\nUpgrade: websocket\r\n\r\n').encode()+data)
            await writer.drain()
            await reader.readuntil(b'\r\n\r\n')
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)),2),data)
            writer.close(); await writer.wait_closed()

    async def test_connect_root_preserves_raw_binary_without_extra_header(self):
        reader, writer = await self.connect()
        data = b'\x00\x38\x38\x00\xffbinary'
        writer.write(b'CONNECT / HTTP/1.1\r\nHost: vpn.example.com\r\n\r\n' + data)
        await writer.drain()
        await reader.readuntil(b'\r\n\r\n')
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 2), data)
        writer.close()
        await writer.wait_closed()

    async def test_unknown_destination_denied(self):
        reader, writer = await self.connect()
        writer.write(b'GET /arbitrary HTTP/1.1\r\nX-Real-Host: 192.0.2.1:22\r\n\r\n')
        await writer.drain()
        self.assertIn(b'404', await reader.read())
        writer.close()
        await writer.wait_closed()


if __name__ == '__main__':
    unittest.main()
