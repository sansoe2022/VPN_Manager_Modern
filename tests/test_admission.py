import concurrent.futures
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import admission


class Admission(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.core=SimpleNamespace(managed=lambda user:None, load=lambda:{'limiter_enabled':True})
        for target,value in [('ROOT',Path(self.temp.name)),('observed',lambda m:{}),('process',lambda pid:(1,'start')),('vpn_status',lambda:None)]:
            item=patch.object(admission,target,value); item.start(); self.addCleanup(item.stop)
        item=patch.object(admission.accounts,'load',return_value={'a':{'limit':2}}); item.start(); self.addCleanup(item.stop)

    def test_one_shared_limit_and_idempotent_existing_session(self):
        self.assertTrue(admission.reserve(self.core,'a','ssh','1',1))
        self.assertTrue(admission.reserve(self.core,'a','openvpn','127.0.0.1:1',2))
        self.assertFalse(admission.reserve(self.core,'a','udp','peer',3))
        self.assertTrue(admission.reserve(self.core,'a','ssh','1',1))
        admission.release('ssh','1')
        self.assertTrue(admission.reserve(self.core,'a','udp','peer',3))

    def test_parallel_protocol_requests_cannot_overbook(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            accepted=list(pool.map(lambda number:admission.reserve(self.core,'a',['ssh','udp','openvpn'][number%3],str(number),number+1),range(30)))
        self.assertEqual(sum(accepted),2)

    def test_observed_session_is_not_double_counted_and_dead_pid_releases_slot(self):
        self.assertTrue(admission.reserve(self.core,'a','ssh','1',1))
        with patch.object(admission,'observed',return_value={'ssh:1':'a'}):
            self.assertTrue(admission.reserve(self.core,'a','udp','peer',2))
        with patch.object(admission,'process',side_effect=lambda pid:None if pid==1 else (1,'start')):
            self.assertTrue(admission.reserve(self.core,'a','openvpn','new',3))

    def test_off_still_tracks_sessions_for_later_activation(self):
        self.core.load=lambda:{'limiter_enabled':False}
        for i in range(3): self.assertTrue(admission.reserve(self.core,'a','udp',str(i),i+1))
        self.core.load=lambda:{'limiter_enabled':True}
        self.assertFalse(admission.reserve(self.core,'a','ssh','new',4))

    def test_unmanaged_administrator_skips_the_account_hook(self):
        self.core.users=lambda:['a']
        with patch.dict(admission.os.environ,{'PAM_USER':'root'}), patch.object(admission,'reserve') as reserve:
            self.assertTrue(admission.pam(self.core))
            reserve.assert_not_called()

    def test_ssh_connection_owner_is_outside_temporary_pam_helper(self):
        root=Path(self.temp.name)
        for pid,title in [(90,'sshd: a [priv]'),(70,'sshd: a [priv]'),(45,'sshd [listener]')]:
            directory=root/str(pid); directory.mkdir()
            (directory/'comm').write_text('sshd')
            (directory/'cmdline').write_bytes(title.encode()+b'\0')
        parents={90:(70,'helper'),70:(45,'connection'),45:(1,'listener')}
        with patch.object(admission,'process',side_effect=lambda pid:parents.get(pid)), \
             patch.object(admission,'Path',side_effect=lambda *parts:root.joinpath(*parts[1:])):
            self.assertEqual(admission.ssh_owner(90),70)
