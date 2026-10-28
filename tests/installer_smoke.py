"""Exercise fresh/URL-restore prompts and argument forwarding in a disposable container."""
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time

if os.geteuid() or not Path('/.dockerenv').exists(): raise SystemExit('Disposable root container required')
source=Path(__file__).resolve().parents[1]
Path('/run/systemd/system').mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory() as directory:
    commands=Path(directory)
    for name,body in {'apt-get':'exit 0','systemctl':'exit 1', 'python3': 'printf "STUBPY %s\\n" "$*" >>/tmp/install-calls\nexit 0'}.items():
        target=commands/name; target.write_text('#!/bin/bash\n'+body+'\n'); target.chmod(0o755)
    environment={**os.environ,'PATH':str(commands)+':'+os.environ['PATH']}
    def interactive(answer):
        pid,fd=pty.fork()
        if not pid: os.execvpe('bash',['bash',str(source/'install.sh')],environment)
        os.write(fd,answer.encode())
        output=b''; deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if select.select([fd],[],[],.1)[0]:
                try: block=os.read(fd,65536)
                except OSError: break
                if not block: break
                output+=block
        else:
            os.kill(pid,9); raise AssertionError('Installer prompt timed out')
        _,status=os.waitpid(pid,0); os.close(fd)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0,output.decode(errors='replace')
        return output.decode(errors='replace')
    first=interactive('1\n')
    assert 'Fresh installation' in first and 'Restore from encrypted backup URL' in first
    assert ' restore ' not in Path('/tmp/install-calls').read_text()
    second=interactive('2\nhttps://example.com/backup.vpnbak\n')
    assert 'Backup URL:' in second
    assert ' restore https://example.com/backup.vpnbak' in Path('/tmp/install-calls').read_text()
    subprocess.run(['bash',str(source/'install.sh'),'--restore-url','https://example.com/other.vpnbak','--password-file','/root/pass','--endpoint','203.0.113.1'],env=environment,check=True,stdout=subprocess.DEVNULL)
    calls=Path('/tmp/install-calls').read_text()
    assert 'restore https://example.com/other.vpnbak --password-file /root/pass --endpoint 203.0.113.1' in calls
print('PASS installer interactive fresh/URL-restore choices and noninteractive restore arguments')
