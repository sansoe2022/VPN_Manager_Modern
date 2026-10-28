"""The original, intentionally public VPN_Manager shared OpenVPN key bundle."""
import hashlib
from pathlib import Path
import zipfile
import subprocess

BUNDLE = Path(__file__).parent / 'assets/openvpn-shared.zip'
SHA256 = '2819e194803280f07e17f6f16390d104c35736fca1312267efa19a9d22e2e194'
FILES = {'ca.crt': 'vpnmanager-ca.crt', 'server.crt': 'vpnmanager-server.crt',
         'server.key': 'vpnmanager-server.key', 'dh.pem': 'vpnmanager-dh.pem',
         'ta.key': 'vpnmanager-tls.key'}


def install(m, directory):
    if hashlib.sha256(BUNDLE.read_bytes()).hexdigest() != SHA256:
        raise ValueError('The original shared key bundle checksum does not match.')
    with zipfile.ZipFile(BUNDLE) as archive:
        for source, destination in FILES.items():
            # Fixed member names; no archive path extraction.
            m.write(directory / destination, archive.read(source).decode('ascii'))
    m.run('openssl', 'verify', '-CAfile', str(directory / 'vpnmanager-ca.crt'),
          str(directory / 'vpnmanager-server.crt'), stdout=subprocess.DEVNULL)
