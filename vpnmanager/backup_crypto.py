"""Password-protected backups: AES-256-CBC with encrypt-then-HMAC-SHA256."""
import base64
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import tempfile

MAGIC = b'VPNMODERN-BACKUP-2\n'
LIMIT = 1024 * 1024 * 1024


def keys(password, salt):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError('Backup password must contain at least 12 characters.')
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000, 64)


def crypt(source, target, key, decrypt=False):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, base64.b64encode(key) + b'\n')
        os.close(write_fd)
        write_fd = None
        subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', '-md', 'sha256',
            *(['-d'] if decrypt else []), '-pass', f'fd:{read_fd}', '-in', str(source), '-out', str(target)],
            pass_fds=(read_fd,), check=True, capture_output=True)
        Path(target).chmod(0o600)
    except BaseException:
        Path(target).unlink(missing_ok=True)
        raise
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def encrypt(source, target, password):
    salt = os.urandom(16)
    secret = keys(password, salt)
    header = MAGIC + salt
    with tempfile.TemporaryDirectory(prefix='vpnmanager-encrypt-') as directory:
        cipher = Path(directory) / 'cipher'
        crypt(source, cipher, secret[:32])
        mac = hmac.new(secret[32:], header, hashlib.sha256)
        with Path(target).open('wb') as output, cipher.open('rb') as input_file:
            Path(target).chmod(0o600)
            output.write(header)
            while True:
                block = input_file.read(1024 * 1024)
                if not block:
                    break
                mac.update(block)
                output.write(block)
            output.write(mac.digest())
    return Path(target)


def decrypt(source, target, password):
    source = Path(source)
    if not len(MAGIC) + 16 + 48 <= source.stat().st_size <= LIMIT:
        raise ValueError('Invalid backup size.')
    with source.open('rb') as input_file, tempfile.TemporaryDirectory(prefix='vpnmanager-decrypt-') as directory:
        if input_file.read(len(MAGIC)) != MAGIC:
            raise ValueError('This is not an encrypted VPN Manager backup.')
        salt = input_file.read(16)
        secret = keys(password, salt)
        mac = hmac.new(secret[32:], MAGIC + salt, hashlib.sha256)
        remaining = source.stat().st_size - len(MAGIC) - 16 - 32
        cipher = Path(directory) / 'cipher'
        with cipher.open('wb') as output:
            cipher.chmod(0o600)
            while remaining:
                block = input_file.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError('Truncated backup.')
                mac.update(block)
                output.write(block)
                remaining -= len(block)
        if not hmac.compare_digest(input_file.read(32), mac.digest()):
            raise ValueError('Wrong backup password or damaged backup. Nothing was restored.')
        crypt(cipher, target, secret[:32], decrypt=True)
    return Path(target)
