"""Real Hysteria v1 client/server, shared Unix credentials and unified online API."""
import json
import base64
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from urllib.request import Request, urlopen
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import online
import udp_runtime

if os.geteuid() or not Path('/.dockerenv').exists():
    raise SystemExit('Run only in a disposable root container.')
shutil.copytree('/src/vpnmanager', '/usr/local/lib/vpnmanager', dirs_exist_ok=True)
udp_runtime.BINARY.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2('/tmp/hysteria-test', udp_runtime.BINARY)
udp_runtime.BINARY.chmod(0o755)
real_run = manager.run

def run(*args, **kwargs):
    if args[0] in ('systemctl', 'sysctl'):
        return subprocess.CompletedProcess(args, 0, '')
    return real_run(*args, **kwargs)

def start(name, config):
    config['enabled'] = sorted(set(config['enabled']) | {name})
    manager.save(config)

with patch.object(manager, 'run', side_effect=run), patch.object(manager, 'start', side_effect=start):
    manager.initialize()
    config = manager.load()
    config.update(endpoint=os.environ.get('UDP_TEST_ENDPOINT','localhost'), checkuser=True)
    manager.create_user('a', 1, secret='1')
    udp_runtime.configure(manager, config, 36712)

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            body = self.request.recv(65536)
            if not body: break
            self.request.sendall(body)
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)
tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 9001), TCP)
tcp.daemon_threads = True
udp = socketserver.ThreadingUDPServer(('127.0.0.1', 9002), UDP)
for service in (tcp, udp):
    threading.Thread(target=service.serve_forever, daemon=True).start()
server_log = open('/tmp/udp-server.log', 'w')
server = subprocess.Popen(['python3', '/usr/local/lib/vpnmanager/manager.py', 'serve-udp'], stdout=server_log, stderr=subprocess.STDOUT)
client = None

def connect(password):
    data = {'server':'127.0.0.1:10000-50000', 'server_name':config['endpoint'], 'protocol':'udp', 'up_mbps':10, 'down_mbps':10,
            'auth_str':'a:' + password, 'obfs':'svpn', 'ca':'/etc/vpnmanager/udp-ca.crt',
            'quit_on_disconnect':True, 'retry':0, 'handshake_timeout':3, 'idle_timeout':4,
            'relay_tcp':{'listen':'127.0.0.1:9000','remote':'127.0.0.1:9001'},
            'relay_udp':{'listen':'127.0.0.1:9003','remote':'127.0.0.1:9002'}}
    manager.write('/tmp/udp-client.json', json.dumps(data))
    output = open('/tmp/udp-client.log', 'w')
    process = subprocess.Popen([str(udp_runtime.BINARY), '--no-check', '--log-level', 'info', 'client', '-c', '/tmp/udp-client.json'],stdout=output,stderr=subprocess.STDOUT)
    output.close()
    return process

try:
    time.sleep(.5)
    # Loopback test traffic traverses OUTPUT instead of the external PREROUTING hook.
    subprocess.run(['iptables','-t','nat','-A','OUTPUT','-p','udp','-d','127.0.0.1','-j','VPNMANAGER_UDP'],check=True)
    client = connect('1')
    for _ in range(60):
        time.sleep(.1)
        if online.collect()['users']['udp'] == ['a']:
            break
        if client.poll() is not None: raise AssertionError('UDP client exited early')
    else: raise AssertionError('UDP authenticated session not counted')
    with socket.create_connection(('127.0.0.1', 9000), timeout=5) as connection:
        connection.sendall(b'shared-account-tcp-over-quic')
        assert connection.recv(4096) == b'shared-account-tcp-over-quic'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)
        connection.sendto(b'native-udp-relay', ('127.0.0.1',9003))
        assert connection.recv(4096) == b'native-udp-relay'
    assert online.collect()['total'] == 1
    api=online.ThreadingHTTPServer(('127.0.0.1',0),online.Handler)
    api_thread=threading.Thread(target=api.serve_forever,daemon=True); api_thread.start()
    try:
        auth='Basic '+base64.b64encode(b'a:1').decode()
        with urlopen(Request(f'http://127.0.0.1:{api.server_port}/checkuser',headers={'Authorization':auth})) as response:
            result=json.load(response)
        assert set(result)=={'username','connection_limit','expire_date'}
        assert result['username']=='a' and result['connection_limit']==1
        print('PASS real CheckUser API with Unix password authentication and only three requested fields',flush=True)
    finally: api.shutdown(); api.server_close(); api_thread.join()
    print('PASS shared one-character user/password, verified TLS, real TCP/UDP relay and unified online count', flush=True)
    client.terminate(); client.wait(timeout=5)
    for _ in range(100):
        time.sleep(.1)
        if not udp_runtime.sessions(): break
    assert not udp_runtime.sessions(), 'Disconnected UDP session remains online'
    manager.set_password('a', '2')
    client = connect('1')
    client.wait(timeout=8)
    assert client.returncode != 0, 'Old password unexpectedly connected'
    assert not udp_runtime.sessions(), 'Old password accepted after change'
    client = connect('2')
    for _ in range(60):
        time.sleep(.1)
        if udp_runtime.sessions() == ['a']: break
    assert udp_runtime.sessions() == ['a'], 'New shared password was not accepted'
    client.terminate(); client.wait(timeout=5)
    for _ in range(100):
        time.sleep(.1)
        if not udp_runtime.sessions(): break
    assert not udp_runtime.sessions()
    subprocess.run(['chage', '-E', '2000-01-01', 'a'], check=True)
    client = connect('2'); client.wait(timeout=8)
    assert client.returncode != 0, 'Expired credentials unexpectedly connected'
    assert not udp_runtime.sessions(), 'Expired account accepted by UDP'
    print('PASS password change, disconnect cleanup and account expiry without a second user database', flush=True)
except BaseException:
    server_log.flush()
    print(Path('/tmp/udp-server.log').read_text())
    print(Path('/tmp/udp-client.log').read_text() if Path('/tmp/udp-client.log').exists() else '')
    raise
finally:
    subprocess.run(['iptables','-t','nat','-D','OUTPUT','-p','udp','-d','127.0.0.1','-j','VPNMANAGER_UDP'],check=False)
    for process in (client, server):
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    server_log.close()
    for service in (tcp, udp): service.shutdown(); service.server_close()
