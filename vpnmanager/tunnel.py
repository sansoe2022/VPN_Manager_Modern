"""Bounded HTTP upgrade / RFC 6455 TCP tunnel to fixed local backends."""
import asyncio
import base64
import hashlib
import struct
import re
from urllib.parse import urlsplit

MAX_FRAME = 1024 * 1024


async def frame(reader):
    first, second = await reader.readexactly(2)
    if first & 0x70 or not second & 0x80:
        raise ValueError('Invalid WebSocket frame')
    opcode, size = first & 15, second & 127
    if size == 126:
        size = struct.unpack('!H', await reader.readexactly(2))[0]
    elif size == 127:
        size = struct.unpack('!Q', await reader.readexactly(8))[0]
    if size > MAX_FRAME or (opcode >= 8 and (size > 125 or not first & 128)):
        raise ValueError('Invalid WebSocket frame size')
    mask = await reader.readexactly(4)
    data = await reader.readexactly(size)
    return opcode, bytes(value ^ mask[index % 4] for index, value in enumerate(data))


def packet(data, opcode=2):
    size = len(data)
    header = bytes([128 | opcode, size]) if size < 126 else bytes([128 | opcode, 126]) + struct.pack('!H', size)
    return header + data


async def relay(reader, writer):
    while True:
        data = await reader.read(65535)
        if not data:
            return
        writer.write(data)
        await writer.drain()


RAW_METHODS = ('GET', 'CONNECT', 'CF-RAY', 'PATCH', 'POST', 'PUT', 'HEAD', 'OPTIONS', 'DELETE')


async def legacy_relay(reader, writer):
    """Strip bounded pipelined carrier headers, preserving the first native data byte."""
    markers = tuple((method + ' ').encode() for method in RAW_METHODS)
    count, total = 0, 0
    while True:
        prefix = b''
        while prefix not in markers:
            part = await reader.read(1) if not prefix else await asyncio.wait_for(reader.read(1), 10)
            if not part:
                if prefix:
                    writer.write(prefix)
                    await writer.drain()
                return
            prefix += part
            if not any(marker.startswith(prefix) for marker in markers):
                writer.write(prefix)
                await writer.drain()
                await relay(reader, writer)
                return
        count += 1
        if count > 4:
            raise ValueError('Too many carrier request headers')
        rest = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
        header = prefix + rest
        total += len(header)
        if len(header) > 16384 or total > 32768 or not re.fullmatch(rb'[A-Z-]+ [^\r\n ]+ HTTP/1\.[01]', header.split(b'\r\n', 1)[0]):
            raise ValueError('Invalid carrier request header')
        # These headers select no destinations and produce no extra HTTP responses.
        # The listener's already-validated local SSH/OpenVPN route stays fixed.


async def ws_to_tcp(reader, target, client):
    while True:
        opcode, data = await frame(reader)
        if opcode == 8:
            client.write(packet(b'', 8))
            await client.drain()
            return
        if opcode == 9:
            client.write(packet(data, 10))
            await client.drain()
        elif opcode in (0, 1, 2):
            target.write(data)
            await target.drain()
        elif opcode != 10:
            raise ValueError('Unsupported WebSocket opcode')


async def tcp_to_ws(reader, writer):
    while True:
        data = await reader.read(65535)
        if not data:
            return
        writer.write(packet(data))
        await writer.drain()


def routes(ssh_port, openvpn_port, enabled, default='ssh'):
    result = {}
    if 'ssh' in enabled:
        result.update({'/': ssh_port, '/ssh': ssh_port})
    if 'openvpn' in enabled:
        result.update({'/openvpn': openvpn_port, '/ovpn': openvpn_port})
        result.setdefault('/', openvpn_port)
    if default == 'openvpn' and '/openvpn' in result:
        result['/'] = openvpn_port
    return result


def select_backend(method, path, headers, backends):
    # Original SSHPlus clients use absolute URLs and arbitrary payload paths.
    if path.startswith(('http://', 'https://')):
        path = urlsplit(path).path or '/'
    path = path.split('?', 1)[0]
    target = headers.get('x-real-host')
    if target is None and method == 'CONNECT' and not path.startswith('/'):
        target = path
    if target is not None:
        match = re.fullmatch(r'(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\]):(\d{1,5})', target.strip())
        if not match:
            return None
        number = int(match[1])
        for route, legacy_port in (('/ssh', 22), ('/openvpn', 1194)):
            if route in backends and number in (legacy_port, backends[route]):
                return backends[route]
        return None
    if path in ('/ssh', '/openvpn', '/ovpn'):
        return backends.get(path)
    # The original raw proxy ignores the carrier's URL when no local target is given.
    return backends.get(path, backends.get('/'))


async def handle(reader, writer, backends):
    target = None
    tasks = []
    try:
        header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
        if len(header) > 16384:
            raise ValueError('Headers too large')
        lines = header.decode('ascii').split('\r\n')
        method, path, version = lines[0].split()
        headers = {}
        for line in lines[1:]:
            if line:
                key, value = line.split(':', 1)
                headers[key.lower()] = value.strip()
        # Legacy destination headers are limited to configured SSH/OpenVPN backends.
        backend = select_backend(method, path, headers, backends)
        if method not in RAW_METHODS or not version.startswith('HTTP/1.') or backend is None:
            writer.write(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            return
        key = headers.get('sec-websocket-key')
        if key:
            if (method != 'GET' or len(base64.b64decode(key, validate=True)) != 16
                    or headers.get('sec-websocket-version') != '13'
                    or headers.get('upgrade', '').lower() != 'websocket'
                    or 'upgrade' not in headers.get('connection', '').lower()):
                raise ValueError('Invalid WebSocket handshake')
        try:
            upstream, target = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', backend), 10)
        except (OSError, asyncio.TimeoutError):
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            return
        if key:
            accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
        elif method == 'CONNECT':
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n')
        await writer.drain()
        if key:
            tasks = [asyncio.create_task(ws_to_tcp(reader, target, writer)), asyncio.create_task(tcp_to_ws(upstream, writer))]
        else:
            incoming = legacy_relay(reader, target)
            tasks = [asyncio.create_task(incoming), asyncio.create_task(relay(upstream, writer))]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (target, writer):
            if stream:
                stream.close()
                try:
                    await stream.wait_closed()
                except OSError:
                    pass


async def serve(host, port, ssh_port, openvpn_port, enabled=('ssh', 'openvpn'), default='ssh'):
    active = 0
    backends = routes(ssh_port, openvpn_port, enabled, default)

    async def limited(reader, writer):
        nonlocal active
        if active >= 512:
            writer.close()
            return
        active += 1
        try:
            await handle(reader, writer, backends)
        finally:
            active -= 1

    server = await asyncio.start_server(limited, host, port, limit=16384)
    async with server:
        await server.serve_forever()


async def serve_listeners(host, listeners, ssh_port, openvpn_port):
    if not listeners:
        raise ValueError('No proxy listeners configured. Use menu 10 -> 05.')
    tasks = [asyncio.create_task(serve(host, entry['port'], ssh_port, openvpn_port,
                                     entry['backends'], entry['default'])) for entry in listeners]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
