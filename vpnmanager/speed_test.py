"""HTTPS bandwidth test without the obsolete speedtest-cli server API."""
import os
import statistics
import time
from urllib.request import Request, urlopen

HEADERS = {'User-Agent': 'Mozilla/5.0 VPNManagerModern/1.0', 'Cache-Control': 'no-cache'}


def download(url, size):
    start, received = time.monotonic(), 0
    with urlopen(Request(url, headers=HEADERS), timeout=30) as response:
        while received < size:
            chunk = response.read(min(262144, size - received))
            if not chunk:
                break
            received += len(chunk)
    if received != size:
        raise ValueError('The speed-test server returned incomplete download data.')
    return received * 8 / max(time.monotonic() - start, .000001) / 1000000


def measure(base='https://speed.cloudflare.com', down_size=25000000, up_size=8000000):
    timings = []
    for _ in range(3):
        start = time.monotonic()
        with urlopen(Request(base + '/__down?bytes=0', headers=HEADERS), timeout=20) as response:
            response.read(1024)
        timings.append((time.monotonic() - start) * 1000)
    print(f'HTTPS latency: {statistics.median(timings):.1f} ms', flush=True)
    print(f'Downloading {down_size / 1000000:g} MB...', flush=True)
    down = download(base + '/__down?bytes=' + str(down_size), down_size)
    print(f'Download: {down:.2f} Mbps', flush=True)
    print(f'Uploading {up_size / 1000000:g} MB...', flush=True)
    payload = os.urandom(up_size)
    start = time.monotonic()
    with urlopen(Request(base + '/__up', data=payload, headers={**HEADERS, 'Content-Type': 'application/octet-stream'}), timeout=30) as response:
        response.read(65536)
    up = up_size * 8 / max(time.monotonic() - start, .000001) / 1000000
    print(f'Upload: {up:.2f} Mbps', flush=True)
    return down, up


def run():
    print('HTTPS bandwidth test using Cloudflare (about 33 MB).', flush=True)
    try:
        return measure()
    except (OSError, ValueError) as error:
        print(f'Primary test unavailable: {error}. Trying OVH download server...', flush=True)
        try:
            down = download('https://proof.ovh.net/files/10Mb.dat', 10000000)
            print(f'Download (OVH): {down:.2f} Mbps; upload unavailable on this fallback server.')
            return down, None
        except (OSError, ValueError) as fallback:
            raise ValueError(f'No bandwidth-test server was reachable: {fallback}. Check outbound HTTPS/DNS.') from None
