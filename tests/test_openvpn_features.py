import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import classic
import manager
import online
import profile_links
import shared_keys
import tunnel


class ShortCredentials(unittest.TestCase):
    def test_single_character_username_and_password_are_accepted(self):
        self.assertEqual(manager.valid_user('a'), 'a')
        self.assertEqual(manager.validate_password('1'), '1')
        for value in ('', 'a:b', 'a\nb', 'a\0b'):
            with self.assertRaises(ValueError):
                manager.validate_password(value)
        with patch.object(manager, 'run') as run:
            manager.set_password('a', '1')
        run.assert_called_once_with('chpasswd', '-c', 'SHA512', input='a:1\n')


class SharedKeys(unittest.TestCase):
    def test_original_bundle_copied_identically_on_two_servers(self):
        core = SimpleNamespace(write=manager.write, run=Mock())
        with tempfile.TemporaryDirectory() as temp, zipfile.ZipFile(shared_keys.BUNDLE) as bundle:
            for number in ('first', 'second'):
                directory = Path(temp) / number
                shared_keys.install(core, directory)
                for source, target in shared_keys.FILES.items():
                    self.assertEqual(hashlib.sha256((directory / target).read_bytes()).digest(),
                                     hashlib.sha256(bundle.read(source)).digest())
                    self.assertEqual((directory / target).stat().st_mode & 0o777, 0o600)

    def test_changed_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / 'bad.zip'
            altered.write_bytes(b'not the original bundle')
            with patch.object(shared_keys, 'BUNDLE', altered):
                with self.assertRaises(ValueError):
                    shared_keys.install(Mock(), Path(temp) / 'target')


class Profiles(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root_patch = patch.object(profile_links, 'ROOT', Path(self.directory.name) / 'links')
        self.root_patch.start()
        self.body = b'client\nauth-user-pass\n<ca>PUBLIC CERTIFICATE</ca>\n<tls-auth>SHARED STATIC KEY</tls-auth>\n'
        def export(config, output):
            manager.write(output, self.body.decode())
        self.core = SimpleNamespace(endpoint=manager.endpoint, port=manager.port, write=manager.write, export_client=export)
        self.config = {'endpoint': 'vpn.example.com', 'online_port': 81}

    def tearDown(self):
        self.root_patch.stop()
        self.directory.cleanup()

    def test_expiry_revoke_modes_and_no_server_private_key(self):
        with patch.object(profile_links.time, 'time', return_value=1000):
            link, expires = profile_links.create(self.core, self.config, 1)
        path = urlsplit(link).path
        self.assertEqual(expires, 1060)
        self.assertEqual(profile_links.read(path, now=1059), self.body)
        self.assertIsNone(profile_links.read(path, now=1060))
        self.assertEqual(len(list(profile_links.ROOT.iterdir())), 1)
        self.assertEqual(profile_links.cleanup(now=1060), 1)
        self.assertIsNone(profile_links.read(path, now=1001))
        for invalid in ('/profiles/../../etc/shadow', '/profiles/%2e%2e/client.ovpn', '/profiles/list'):
            self.assertIsNone(profile_links.read(invalid))
        self.body = b'-----BEGIN PRIVATE KEY-----\nnot real key material\n'
        with self.assertRaises(ValueError):
            profile_links.create(self.core, self.config)
        self.assertEqual(list(profile_links.ROOT.iterdir()), [])

    def test_http_get_head_download_headers_and_redacted_log(self):
        link, _ = profile_links.create(self.core, self.config)
        path = urlsplit(link).path
        token = path.split('/')[2]
        server = online.ThreadingHTTPServer(('127.0.0.1', 0), online.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        logs = io.StringIO()
        with contextlib.redirect_stderr(logs):
            thread.start()
            try:
                url = f'http://127.0.0.1:{server.server_port}' + path
                with urlopen(url) as response:
                    self.assertEqual(response.read(), self.body)
                    self.assertIn('client.ovpn', response.headers['Content-Disposition'])
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                with urlopen(Request(url, method='HEAD')) as response:
                    self.assertEqual(response.read(), b'')
                    self.assertEqual(int(response.headers['Content-Length']), len(self.body))
                self.assertEqual(profile_links.cleanup(force=True), 1)
                with self.assertRaises(HTTPError) as error:
                    urlopen(url)
                self.assertEqual(error.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
        self.assertNotIn(token, logs.getvalue())
        self.assertIn('[redacted]', logs.getvalue())

    def test_online_app_limit_updates_without_restarting_server(self):
        config = Path(self.directory.name) / 'config.json'
        server = online.ThreadingHTTPServer(('127.0.0.1', 0), online.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with patch.object(online, 'CONFIG_PATH', config), patch.object(online, 'collect', return_value={'total': 2}), contextlib.redirect_stderr(io.StringIO()):
            thread.start()
            try:
                for limit in (5, 1234):
                    manager.write(config, json.dumps({'online_app_limit': limit}))
                    with urlopen(f'http://127.0.0.1:{server.server_port}/server/online_app') as response:
                        self.assertEqual(json.load(response), {'onlines': '2', 'limite': str(limit)})
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_custom_https_url_and_credential_url_rejection(self):
        self.assertEqual(profile_links.base_url(self.core, {**self.config, 'download_base_url': 'https://files.example.com/vpn/'}), 'https://files.example.com/vpn')
        for value in ('https://user:pass@vpn.example.com', 'file:///etc', 'https://vpn.example.com?token=x'):
            with self.assertRaises(ValueError):
                profile_links.base_url(self.core, {**self.config, 'download_base_url': value})


class ProxyAndBanner(unittest.TestCase):
    def test_endpoint_detection_and_enter_default(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'8.8.4.4\n'
        with patch.object(manager, 'urlopen', return_value=response):
            self.assertEqual(manager.detect_public_ip(), '8.8.4.4')
        config = {'endpoint': ''}
        with patch.object(manager, 'detect_public_ip', return_value='8.8.4.4'), \
             patch.object(manager, 'save'), patch('builtins.input', return_value='') as prompt:
            classic.Classic(manager).public_endpoint(config)
        self.assertEqual(config['endpoint'], '8.8.4.4')
        self.assertIn('[8.8.4.4]', prompt.call_args.args[0])

    def test_banner_excludes_unmanaged_and_ephemeral_ports(self):
        config = {'enabled': ['tunnel', 'openvpn', 'online'], 'tunnel_port': 80,
                  'openvpn_port': 1194, 'online_port': 81, 'ssh_port': 2222, 'ssh_bind': '127.0.0.1'}
        text = '\n'.join(f'tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*' for port in (22, 80, 81, 1194, 2222, 56001))
        self.assertEqual(classic.connection_ports(config, text), {'tcp': {80, 1194}, 'udp': set()})
        config['ssh_bind'] = '0.0.0.0'
        self.assertEqual(classic.connection_ports(config, text)['tcp'], {80, 1194, 2222})

    def test_proxy_setup_provisions_ssh_and_openvpn_instead_of_requiring_ssh_first(self):
        config = {'enabled': [], 'tunnel_port': 80, 'openvpn_port': 1194}
        with patch.object(manager, 'Path') as path, patch.object(manager, 'free_port'), \
             patch.object(manager, 'configure_ssh') as ssh, patch.object(manager, 'configure') as configure, \
             patch.object(manager, 'run'), contextlib.redirect_stdout(io.StringIO()):
            path.return_value.exists.return_value = False
            manager.configure_proxy(config, 80, ['ssh', 'openvpn'])
        ssh.assert_called_once_with(config, 2222, '127.0.0.1')
        self.assertEqual(config['proxy_backends'], ['ssh', 'openvpn'])
        self.assertEqual(configure.call_args_list, [call('openvpn', config, 1194), call('tunnel', config, 80)])

    def test_openvpn_only_proxy_does_not_require_an_ssh_backend(self):
        config = {'enabled': [], 'tunnel_port': 80, 'openvpn_port': 1194}
        with patch.object(manager, 'free_port'), patch.object(manager, 'configure_ssh') as ssh, \
             patch.object(manager, 'configure'), contextlib.redirect_stdout(io.StringIO()):
            manager.configure_proxy(config, 80, ['openvpn'])
        ssh.assert_not_called()

    def test_proxy_paths_and_legacy_local_headers_select_only_enabled_backends(self):
        both = tunnel.routes(2222, 1194, ['ssh', 'openvpn'])
        self.assertEqual(tunnel.select_backend('GET', '/ssh', {}, both), 2222)
        self.assertEqual(tunnel.select_backend('GET', '/openvpn', {}, both), 1194)
        self.assertEqual(tunnel.select_backend('GET', '/', {'x-real-host': '127.0.0.1:1194'}, both), 1194)
        self.assertEqual(tunnel.select_backend('GET', '/legacy-payload', {'x-real-host': '0.0.0.0:1194'}, both), 1194)
        self.assertEqual(tunnel.select_backend('CONNECT', 'example.com:443', {'x-real-host': 'localhost:1194'}, both), 1194)
        self.assertEqual(tunnel.select_backend('GET', 'http://example.com/openvpn', {}, both), 1194)
        self.assertEqual(tunnel.routes(2222, 1194, ['ssh', 'openvpn'], 'openvpn')['/'], 1194)
        default_vpn = tunnel.routes(2222, 1194, ['ssh', 'openvpn'], 'openvpn')
        self.assertEqual(tunnel.select_backend('GET', '/carrier-path', {}, default_vpn), 1194)
        self.assertEqual(tunnel.select_backend('CONNECT', '127.0.0.1:1194', {}, both), 1194)
        self.assertEqual(tunnel.select_backend('CONNECT', '127.0.0.1:22', {}, both), 2222)
        for host in ('127.0.0.1.evil:22', '127.0.0.1:3306', '192.0.2.1:22'):
            self.assertIsNone(tunnel.select_backend('GET', '/', {'x-real-host': host}, both))
        only_vpn = tunnel.routes(2222, 1194, ['openvpn'])
        self.assertEqual(tunnel.select_backend('GET', '/', {}, only_vpn), 1194)
        self.assertIsNone(tunnel.select_backend('GET', '/ssh', {}, only_vpn))

    def test_banner_ports_include_tcp_udp_ipv6_and_deduplicate(self):
        text = '''tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 128 [::]:22 [::]:*
tcp LISTEN 0 128 127.0.0.1:1194 0.0.0.0:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
'''
        self.assertEqual(classic.listening_ports(text), {'tcp': {22, 1194}, 'udp': {53}})


if __name__ == '__main__':
    unittest.main()
