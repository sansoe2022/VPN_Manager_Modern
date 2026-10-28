import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import classic
import udp_runtime


class UDPTimeout(unittest.TestCase):
    def test_menu_changes_active_udp_and_applies_the_selected_timeout(self):
        config={'enabled':['udp'],'udp_port':36712,'udp_idle_timeout':15}
        core=SimpleNamespace(load=lambda:config,choose=Mock(return_value='timeout'),SERVICES={'udp':'vpnmanager-udp'})
        ui=classic.Classic(core)
        with patch.object(ui,'active',return_value=True), patch('builtins.input',return_value='10'), \
             patch.object(udp_runtime,'configure') as configure, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ui.udp(),'timeout')
        applied=configure.call_args.args
        self.assertIs(applied[0],core)
        self.assertEqual(applied[1]['udp_idle_timeout'],10)
        self.assertEqual(applied[2],36712)
        self.assertIn(('4','Change idle disconnect timeout','timeout'),core.choose.call_args.args[1])
        self.assertEqual(config['udp_idle_timeout'],15)  # Keep the caller snapshot unchanged while applying a new configuration.

    def test_off_service_saves_both_files_without_enabling_or_restarting(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'udp.json'
            path.write_text(json.dumps({'idle_timeout':15,'obfs':'keep','listen':'0.0.0.0:36712'}))
            config={'enabled':[],'udp_port':36712,'udp_idle_timeout':15}
            core=SimpleNamespace(save=Mock(),write=lambda path,text:Path(path).write_text(text),run=Mock())
            with patch.object(udp_runtime,'CONFIG',path), patch.object(udp_runtime,'configure') as configure, \
                 contextlib.redirect_stdout(io.StringIO()):
                udp_runtime.set_idle_timeout(core,config,'10')
            data=json.loads(path.read_text())
            self.assertEqual(data,{'idle_timeout':10,'obfs':'keep','listen':'0.0.0.0:36712'})
            self.assertEqual(core.save.call_args.args[0]['enabled'],[])
            self.assertEqual(core.save.call_args.args[0]['udp_idle_timeout'],10)
            configure.assert_not_called()
            core.run.assert_not_called()

    def test_invalid_timeout_does_not_modify_files_or_services(self):
        core=SimpleNamespace(save=Mock(),write=Mock())
        for value in ('oops',3,121,10.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                udp_runtime.set_idle_timeout(core,{'enabled':['udp'],'udp_port':36712},value)
        core.save.assert_not_called()
        core.write.assert_not_called()
