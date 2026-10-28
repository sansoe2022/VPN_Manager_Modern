"""Bounded downloads with normal HTTPS certificate verification."""
import hashlib
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def fetch(url, target, limit=512 * 1024 * 1024, digest=None, progress=None):
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTP/HTTPS link without embedded credentials.')
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    checksum, total = hashlib.sha256(), 0
    try:
        with urlopen(Request(url, headers={'User-Agent': 'VPN-Manager-Modern'}), timeout=45) as response, target.open('wb') as output:
            target.chmod(0o600)
            expected = int(response.headers.get('Content-Length', '0'))
            if expected > limit:
                raise ValueError('Download exceeds the size limit.')
            updated = time.monotonic()
            if progress:
                progress(0, expected)
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError('Download exceeds the size limit.')
                checksum.update(chunk)
                output.write(chunk)
                if progress and time.monotonic() - updated >= .5:
                    progress(total, expected)
                    updated = time.monotonic()
            if progress:
                progress(total, expected)
        if not total or (digest and checksum.hexdigest() != digest):
            raise ValueError('Download is empty or its checksum does not match.')
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target
