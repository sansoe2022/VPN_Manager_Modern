"""Compile the menu-18 BadVPN source without changing any host services."""
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import extras


def run(*args):
    return subprocess.run(args, check=True, text=True)


def capture(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


core = SimpleNamespace(run=run, capture=capture, save=lambda config: None,
                       service_unit=lambda *args: None, start=lambda *args: None)
with tempfile.TemporaryDirectory() as temp, patch.object(extras, 'package'):
    binary = Path(temp) / 'badvpn-udpgw'
    extras.badvpn(core, {'enabled': []}, 7300, binary=binary)
    run(str(binary), '--help')
print('PASS: pinned BadVPN source compiles and its binary starts.')
