#!/usr/bin/env python3
"""Run the distro Dropbear daemon and record successful authentication events."""
import argparse
import os
import re
import signal
import subprocess
import sys
import dropbear_state
import admission


def serve(port):
    if not 1 <= port <= 65535:
        raise ValueError('Invalid Dropbear port.')
    process = subprocess.Popen(['/usr/sbin/dropbear', '-F', '-E', '-w', '-K', '60', '-I', '300',
        '-p', str(port), '-P', '/run/vpnmanager-dropbear.pid', '-b', '/etc/vpnmanager/banner'],
        stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, bufsize=1)
    data = {}
    dropbear_state.save(data)

    def stop(signum, frame):
        for _, pid in dropbear_state.sessions():
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for line in process.stderr:
            # Dropbear never prints the user's password in these messages.
            sys.stdout.write(line)
            sys.stdout.flush()
            pid = re.match(r'\[(\d+)\]', line)
            auth = re.search(r"(?:Password|Pubkey) auth succeeded for '([a-z][a-z0-9_-]{0,30})'", line)
            if pid and auth:
                try:
                    import manager
                    if not admission.reserve(manager, auth[1], 'dropbear', pid[1], int(pid[1])):
                        os.kill(int(pid[1]), signal.SIGTERM)
                        continue
                    data[pid[1]] = {'user': auth[1], 'start': dropbear_state.identity(int(pid[1]))}
                except (OSError, ValueError):
                    continue
                dropbear_state.save(data)
            elif pid and re.search(r'\b(?:Exit|Disconnect)', line):
                admission.release('dropbear', pid[1])
                data.pop(pid[1], None)
                dropbear_state.save(data)
    finally:
        stop(None, None)
        process.wait()
        dropbear_state.save({})
    if process.returncode not in (0, -signal.SIGTERM):
        raise SystemExit(process.returncode)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', type=int)
    serve(parser.parse_args().port)
