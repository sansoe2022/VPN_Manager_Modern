"""Bounded downloads with normal HTTPS certificate verification."""
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def fetch(url, target, limit=512 * 1024 * 1024, digest=None):
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTP/HTTPS link without embedded credentials.')
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    checksum, total = hashlib.sha256(), 0
    try:
        with urlopen(Request(url, headers={'User-Agent': 'VPN-Manager-Modern'}), timeout=45) as response, target.open('wb') as output:
            target.chmod(0o600)
            if int(response.headers.get('Content-Length', '0')) > limit:
                raise ValueError('Download exceeds the size limit.')
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError('Download exceeds the size limit.')
                checksum.update(chunk)
                output.write(chunk)
        if not total or (digest and checksum.hexdigest() != digest):
            raise ValueError('Download is empty or its checksum does not match.')
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target
