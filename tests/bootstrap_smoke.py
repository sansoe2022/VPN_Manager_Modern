"""Public stdin installer must not reuse an out-of-date working-directory checkout."""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1]
if os.geteuid() != 0:
    raise SystemExit('Run this integration check only in a disposable root container.')
with tempfile.TemporaryDirectory(prefix='bootstrap-check-') as directory:
    root = Path(directory)
    stale = root / 'old-checkout'
    (stale / 'vpnmanager').mkdir(parents=True)
    (stale / 'vpnmanager/manager.py').write_text('# old checkout')
    (stale / 'install.sh').write_text('#!/bin/bash\necho STALE_INSTALL\n')
    commands = root / 'commands'
    commands.mkdir()
    for name, body in {
        'apt-get': '#!/bin/bash\nexit 0\n',
        'git': '''#!/bin/bash
set -eu
destination=${!#}
mkdir -p "$destination"
printf '#!/bin/bash\\necho REMOTE_INSTALL\\n' > "$destination/install.sh"
''',
    }.items():
        path = commands / name
        path.write_text(body)
        path.chmod(0o755)
    result = subprocess.run(['bash'], input=(source / 'Plus').read_text(), text=True,
        capture_output=True, check=True, cwd=stale,
        env={**os.environ, 'PATH': str(commands) + ':' + os.environ['PATH']})
    assert 'REMOTE_INSTALL' in result.stdout and 'STALE_INSTALL' not in result.stdout, result.stdout
print('PASS: public bootstrap fetches current source even from an old checkout.')
