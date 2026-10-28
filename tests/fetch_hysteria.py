"""Download the pinned test binary; TLS and upstream SHA-256 stay verified."""
from pathlib import Path
import platform
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import downloads
import udp_runtime
arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
if arch not in udp_runtime.HASHES: raise SystemExit('Unsupported test architecture')
path=Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/hysteria-test')
downloads.fetch(f'https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-{arch}',path,64*1024*1024,udp_runtime.HASHES[arch])
path.chmod(0o755)
print('Pinned Hysteria v1.3.5 test binary verified.')
