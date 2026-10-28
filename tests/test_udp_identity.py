import contextlib
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import udp_runtime


def run(*args):
    return subprocess.run(args,check=True,text=True,capture_output=True)
core=SimpleNamespace(run=run,capture=lambda *args:run(*args).stdout.strip())


class UDPIdentity(unittest.TestCase):
    def test_endpoint_change_preserves_ca_and_keys_and_updates_ip_san(self):
        with tempfile.TemporaryDirectory() as directory,contextlib.redirect_stdout(io.StringIO()):
            root=Path(directory)
            udp_runtime.certificates(core,'old.example.com',root)
            paths=[root/'udp-ca.crt',root/'udp-ca.key',root/'udp-server.key']
            before={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
            leaf,key=udp_runtime.certificates(core,'127.0.0.2',root)
            self.assertEqual(before,{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
            run('openssl','x509','-in',str(leaf),'-noout','-checkip','127.0.0.2')
            run('openssl','verify','-purpose','sslserver','-CAfile',str(root/'udp-ca.crt'),str(leaf))

    def test_legacy_self_signed_server_can_update_sni_without_changing_trusted_ca(self):
        with tempfile.TemporaryDirectory() as directory,contextlib.redirect_stdout(io.StringIO()):
            root=Path(directory)
            ca,key=root/'udp-ca.crt',root/'udp-server.key'
            run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','30',
                '-subj','/CN=old.example.com','-keyout',str(key),'-out',str(ca))
            original_ca,original_key=ca.read_bytes(),key.read_bytes()
            leaf,_=udp_runtime.certificates(core,'new.example.com',root)
            self.assertEqual(ca.read_bytes(),original_ca)
            self.assertEqual(key.read_bytes(),original_key)
            self.assertEqual((root/'udp-ca.key').read_bytes(),original_key)
            run('openssl','verify','-purpose','sslserver','-CAfile',str(ca),str(leaf))
            run('openssl','x509','-in',str(leaf),'-noout','-checkhost','new.example.com')

if __name__=='__main__': unittest.main()
