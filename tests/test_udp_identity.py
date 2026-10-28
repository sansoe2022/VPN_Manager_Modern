import contextlib
import hashlib
import json
import io
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import udp_runtime


def run(*args):
    return subprocess.run(args,check=True,text=True,capture_output=True)
core=SimpleNamespace(run=run,capture=lambda *args:run(*args).stdout.strip())


class UDPIdentity(unittest.TestCase):
    def test_upgrade_of_running_binary_is_atomic_and_failed_download_preserves_it(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
                root=Path(directory); binary=root/'sleep'
                shutil.copy2('/bin/sleep',binary)
                original=binary.read_bytes(); replacement=Path('/bin/true').read_bytes()
                child=subprocess.Popen(['sleep','30'], executable=str(binary))
                def fetch(url,path,limit,digest):
                    if fail: raise ValueError('Download failed')
                    Path(path).write_bytes(replacement)
                core=SimpleNamespace(port=int,endpoint=lambda value:value,save=lambda config:None,
                    write=lambda path,text:Path(path).write_text(text),service_unit=lambda *args:None,start=lambda *args:None)
                config={'enabled':['udp'],'udp_port':36712,'endpoint':'127.0.0.1'}
                try:
                    with patch.object(udp_runtime,'BINARY',binary), patch.object(udp_runtime,'CONFIG',root/'udp.json'), \
                         patch.object(udp_runtime,'HASHES',{'amd64':hashlib.sha256(replacement).hexdigest()}), \
                         patch.object(udp_runtime.platform,'machine',return_value='x86_64'), \
                         patch.object(udp_runtime,'certificates',return_value=(root/'cert',root/'key')), \
                         patch.object(udp_runtime.downloads,'fetch',side_effect=fetch):
                        if fail:
                            with self.assertRaisesRegex(ValueError,'Download failed'): udp_runtime.configure(core,config,36712)
                        else:
                            udp_runtime.configure(core,config,36712)
                    if not fail:
                        self.assertEqual(config['udp_idle_timeout'],10)
                        self.assertEqual(json.loads((root/'udp.json').read_text())['idle_timeout'],10)
                    self.assertEqual(binary.read_bytes(),original if fail else replacement)
                    self.assertIsNone(child.poll())
                finally:
                    child.terminate(); child.wait(timeout=5)

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
