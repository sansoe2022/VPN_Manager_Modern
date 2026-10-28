import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import accounts
import backup_crypto
import backup_links
import classic
import manager
import online
import private_backup
import speed_test
import udp_runtime
import xui


class Backups(unittest.TestCase):
    def test_encrypted_roundtrip_wrong_password_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plain, encrypted, restored = root/'source', root/'backup', root/'restored'
            body = b'PRIVATE KEY and account password' * 200
            plain.write_bytes(body)
            backup_crypto.encrypt(plain, encrypted, 'a-test-backup-password')
            self.assertNotIn(body[:50], encrypted.read_bytes())
            self.assertEqual(encrypted.stat().st_mode & 0o777, 0o600)
            backup_crypto.decrypt(encrypted, restored, 'a-test-backup-password')
            self.assertEqual(restored.read_bytes(), body)
            restored.unlink()
            with self.assertRaises(ValueError):
                backup_crypto.decrypt(encrypted, restored, 'incorrect-test-password')
            self.assertFalse(restored.exists())
            data = bytearray(encrypted.read_bytes()); data[-40] ^= 1; encrypted.write_bytes(data)
            with self.assertRaises(ValueError):
                backup_crypto.decrypt(encrypted, restored, 'a-test-backup-password')
            self.assertFalse(restored.exists())

    def test_encrypted_download_head_get_expiry_and_log_redaction(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(backup_links, 'ROOT', Path(directory)/'links'):
            plain = Path(directory)/'private.tar.gz'; plain.write_bytes(b'server key and passwords')
            core = SimpleNamespace(endpoint=manager.endpoint, port=manager.port, write=manager.write)
            url, expiry = backup_links.create(core, {'endpoint':'vpn.example.com','online_port':81}, plain, 'a-test-backup-password')
            path = '/' + url.split('/',3)[3]
            token = path.split('/')[2]
            server = online.ThreadingHTTPServer(('127.0.0.1',0),online.Handler)
            worker = threading.Thread(target=server.serve_forever,daemon=True)
            logs = io.StringIO()
            with contextlib.redirect_stderr(logs):
                worker.start()
                try:
                    with urlopen(f'http://127.0.0.1:{server.server_port}'+path) as response:
                        self.assertTrue(response.read().startswith(backup_crypto.MAGIC))
                        self.assertEqual(response.headers['Cache-Control'],'no-store')
                    with urlopen(Request(f'http://127.0.0.1:{server.server_port}'+path, method='HEAD')) as response:
                        self.assertEqual(response.read(), b'')
                        self.assertGreater(int(response.headers['Content-Length']), len(backup_crypto.MAGIC))
                    self.assertIsNone(backup_links.resolve(path, now=expiry))
                    backup_links.cleanup(now=expiry)
                    self.assertIsNone(backup_links.resolve(path))
                finally:
                    server.shutdown(); server.server_close(); worker.join()
            self.assertNotIn(token,logs.getvalue())

    def test_full_backup_paths_remain_restricted(self):
        for path in ('source/manager.py','units/vpnmanager-udp.service','xui-config/x-ui.db','dropbear/dropbear_rsa_host_key'):
            self.assertTrue(private_backup.allowed(path))
        for path in ('../etc/shadow','units/ssh.service','commands/bash','sysctl/other.conf','xui/../../etc/shadow'):
            self.assertFalse(private_backup.allowed(path))
        for path in ('source/file','config/file'):
            member=tarfile.TarInfo(path); member.type=tarfile.SYMTYPE
            archive=Mock(); archive.getmembers.return_value=[member]
            with self.assertRaises(ValueError): private_backup.validate_members(archive)


class AccountsAndInstallers(unittest.TestCase):
    def test_report_displays_saved_password_and_old_account_marker(self):
        core=SimpleNamespace(collect=lambda:{'users':{}},users=lambda:['a','old'])
        ui=classic.Classic(core)
        with patch.object(ui,'metadata',side_effect=[({'password':'1'},False,'2030-01-01',False),({},False,'2030-01-01',False)]), contextlib.redirect_stdout(io.StringIO()) as output:
            ui.report()
        self.assertIn('Password',output.getvalue())
        self.assertIn('(reset to display)',output.getvalue())
        self.assertIn('User       : a',output.getvalue())
        self.assertIn('Password   : 1',output.getvalue())

    def test_requested_xui_os_mapping(self):
        self.assertIn('sansoe2022', xui.source({'ID':'ubuntu','VERSION_ID':'20.04'})[0])
        self.assertIn('alireza0', xui.source({'ID':'ubuntu','VERSION_ID':'24.04'})[0])
        self.assertIn('sansoe2022',xui.source({'ID':'ubuntu','VERSION_ID':'22.04'})[0])
        self.assertIn('sansoe2022',xui.source({'ID':'debian','VERSION_ID':'13'})[0])

    def test_udp_uses_existing_hash_and_expiry_instead_of_a_second_database(self):
        core=SimpleNamespace(managed=Mock(),capture=Mock(return_value='a:$hash:::::::'))
        request={'payload':base64.b64encode(b'a:1').decode()}
        with patch.object(accounts,'load',return_value={}),patch.object(accounts,'verify_password',return_value=True):
            self.assertEqual(udp_runtime.authenticate(core,request),'a')
            core.capture.return_value='a:!$hash:::::::'
            self.assertIsNone(udp_runtime.authenticate(core,request))
            core.capture.return_value='a:$hash::::::1:'
            self.assertIsNone(udp_runtime.authenticate(core,request))

    def test_current_ip_is_offered_even_when_old_endpoint_is_saved(self):
        core=SimpleNamespace(detect_public_ip=lambda:'8.8.4.4', endpoint=manager.endpoint, save=Mock())
        config={'endpoint':'old.example.com'}
        with patch('builtins.input',return_value='') as prompt:
            classic.Classic(core).public_endpoint(config)
        self.assertEqual(config['endpoint'],'8.8.4.4')
        self.assertIn('[8.8.4.4]',prompt.call_args.args[0])

    def test_udp_banner_is_in_udp_section(self):
        data=classic.connection_services({'enabled':['udp'],'udp_port':36712},'udp UNCONN 0 0 0.0.0.0:36712 0.0.0.0:*')
        self.assertEqual(data,{'tcp':[],'udp':[('Hysteria UDP',36712)]})


class Speed(unittest.TestCase):
    def test_download_and_upload_against_local_server(self):
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        seen=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                size=int(self.path.split('bytes=')[1]); self.send_response(200); self.end_headers(); self.wfile.write(b'x'*size)
            def do_POST(self):
                data=self.rfile.read(int(self.headers['Content-Length'])); seen.append(len(data))
                self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            with contextlib.redirect_stdout(io.StringIO()): result=speed_test.measure(f'http://127.0.0.1:{server.server_port}',8192,4096)
            self.assertTrue(all(value>0 for value in result)); self.assertEqual(seen,[4096])
        finally: server.shutdown(); server.server_close(); thread.join()

if __name__=='__main__': unittest.main()
