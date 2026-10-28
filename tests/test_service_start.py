import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import manager
import udp_runtime


class ServiceStartup(unittest.TestCase):
    def test_delayed_udp_listener_can_start_after_the_old_three_second_cutoff(self):
        clock=[0]
        def capture(*args):
            return ('UNCONN listening' if clock[0]>=7 else '') if args[0]=='ss' else 'active'
        def sleep(delay): clock[0]+=delay
        with patch.object(manager,'capture',side_effect=capture), patch.object(manager.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(manager.time,'sleep',side_effect=sleep), contextlib.redirect_stdout(io.StringIO()) as output:
            manager.wait_listener('udp','vpnmanager-udp',36712,123)
        self.assertGreaterEqual(clock[0],7)
        self.assertIn('Waiting for UDP 36712',output.getvalue())

    def test_failed_service_reports_only_logs_since_this_start_attempt(self):
        def capture(*args):
            if args[0]=='ss': return ''
            if args[0]=='systemctl': return 'failed'
            return 'current startup error'
        with patch.object(manager,'capture',side_effect=capture) as command, patch.object(manager.time,'sleep') as sleep:
            with self.assertRaisesRegex(ValueError,'current startup error'):
                manager.wait_listener('udp','vpnmanager-udp',36712,123)
        self.assertIn('--since',command.call_args.args)
        self.assertIn('@123',command.call_args.args)
        sleep.assert_not_called()

    def test_native_failure_is_not_silenced_as_an_intentional_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            binary=root/'native'
            binary.write_text('#!/bin/sh\nexit 7\n'); binary.chmod(0o755)
            config=root/'config.json'; config.write_text(json.dumps({}))
            core=SimpleNamespace(write=lambda path,text:Path(path).write_text(text))
            with patch.object(udp_runtime,'BINARY',binary), patch.object(udp_runtime,'CONFIG',config), \
                 patch.object(udp_runtime,'STATE',root/'state.json'), patch.object(udp_runtime.signal,'signal'):
                self.assertEqual(udp_runtime._serve(core),7)
