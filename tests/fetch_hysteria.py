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
official = '--official' in sys.argv
url = 'https://github.com/apernet/hysteria/releases/download/v1.3.5' if official else udp_runtime.CORE_URL
hashes = {'amd64':'41dc8bc3fff6fc1f031666eb294f10b481b80b66229d7c6aca88398d0fba839d','arm64':'702cd2f3f7bb1d00d463ece4547b6a80de85aa4f6fa8fd1dc7ebd87eb0e2c7b9'} if official else udp_runtime.HASHES
downloads.fetch(f'{url}/hysteria-linux-{arch}',path,64*1024*1024,hashes[arch])
path.chmod(0o755)
print('Pinned Hysteria Modern test binary verified.')
