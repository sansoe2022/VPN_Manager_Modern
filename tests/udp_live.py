"""Real Hysteria v1 client/server, shared Unix credentials and unified online API."""
import json
import base64
import os
from pathlib import Path
import shutil
import socket
import signal
import socketserver
import subprocess
import sys
import threading
import time
from urllib.request import Request, urlopen
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import manager
import admission
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
    config.update(endpoint=os.environ.get('UDP_TEST_ENDPOINT','localhost'), checkuser=True, limiter_enabled=True)
    manager.create_user('a', 1, secret='1')
    manager.create_user('b', 1, secret='1')
    udp_runtime.configure(manager, config, 36712)
    assert json.loads(udp_runtime.CONFIG.read_text())['idle_timeout']==config['udp_idle_timeout']==10

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
server = subprocess.Popen(['python3', '/usr/local/lib/vpnmanager/manager.py', 'serve-udp'], stdout=server_log, stderr=subprocess.STDOUT, start_new_session=True)
client = None
client_b = None
CLIENT = Path('/tmp/hysteria-client-official') if Path('/tmp/hysteria-client-official').exists() else udp_runtime.BINARY

def connect(password, user="a"):
    offset=10 if user=="b" else 0
    data = {'server':'127.0.0.1:10000-50000', 'server_name':config['endpoint'], 'protocol':'udp', 'up_mbps':10, 'down_mbps':10,
            'auth_str':user + ':' + password, 'obfs':'svpn', 'ca':'/etc/vpnmanager/udp-ca.crt',
            'hop_interval':8, 'quit_on_disconnect':True, 'retry':0, 'handshake_timeout':3, 'idle_timeout':20 if user=='b' else 4,
            'relay_tcp':{'listen':'127.0.0.1:'+str(9000+offset),'remote':'127.0.0.1:9001'},
            'relay_udp':{'listen':'127.0.0.1:'+str(9003+offset),'remote':'127.0.0.1:9002'}}
    filename='/tmp/udp-client-'+user+'.json'
    manager.write(filename, json.dumps(data))
    output = open('/tmp/udp-client.log', 'w')
    process = subprocess.Popen([str(CLIENT), '--no-check', '--log-level', 'info', 'client', '-c', filename],stdout=output,stderr=subprocess.STDOUT)
    output.close()
    return process

try:
    for _ in range(150):
        if manager.capture('ss','-H','-lun','sport','=','36712'):
            break
        if server.poll() is not None:
            raise AssertionError('UDP server exited during startup')
        time.sleep(.1)
    else:
        raise AssertionError('UDP server did not open its test listener')
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
    # Change both source and destination UDP ports repeatedly before disconnect.
    before=manager.capture('ss','-H','-uanp')
    time.sleep(9)
    after=manager.capture('ss','-H','-uanp')
    owned=lambda output:{line.split()[3] for line in output.splitlines() if 'pid='+str(client.pid)+',' in line}
    assert owned(before)!=owned(after), 'Native UDP client did not hop its source port'
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
    client_b=connect('1', 'b')
    for _ in range(60):
        time.sleep(.1)
        if sorted(udp_runtime.sessions())==['a','b']: break
    assert sorted(udp_runtime.sessions())==['a','b'], 'Second account behind the same IP failed'
    keys=json.loads(udp_runtime.STATE.read_text())['connections']
    assert len({key.rsplit('#',1)[1] for key in keys})==2, 'Native sessions have no distinct stable connection IDs'
    time.sleep(9)  # Both clients have migrated while remaining authenticated.
    client.kill(); client.wait(timeout=5)  # Abrupt application termination, no QUIC CLOSE.
    for _ in range(100):
        time.sleep(.1)
        if udp_runtime.sessions()==['b']: break
    assert udp_runtime.sessions()==['b'], 'Migration cleanup removed the wrong account or left the dead one'
    assert client_b.poll() is None
    with admission.ledger() as rows:
        assert not any(key.startswith('udp:') and row['user']=='a' for key,row in rows.items())
        assert any(key.startswith('udp:') and row['user']=='b' for key,row in rows.items())
    time.sleep(4)  # A normal 20s-idle client remains live past the manager's 10s idle bound.
    assert udp_runtime.sessions()==['b'] and client_b.poll() is None
    closed=time.monotonic()
    client_b.kill(); client_b.wait(timeout=5)
    for _ in range(200):
        time.sleep(.1)
        if not udp_runtime.sessions(): break
    assert not udp_runtime.sessions(), 'Disconnected UDP session remains online'
    assert time.monotonic()-closed < 15, 'Server did not enforce its negotiated idle bound'
    with admission.ledger() as rows:
        assert not any(key.startswith('udp:') and row['user']=='a' for key,row in rows.items()), 'UDP admission slot remains occupied after disconnect'
    print('PASS actual source-port migration, 1/1 to 0/1 cleanup and shared limiter slot release',flush=True)
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
    for process in (client, client_b, server):
        if process and process.poll() is None:
            if process is server:
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    server_log.close()
    for service in (tcp, udp): service.shutdown(); service.server_close()

assert server.returncode == 0, 'Intentional UDP process-group shutdown returned ' + str(server.returncode)
print('PASS systemd-style SIGTERM to supervisor and native child exits successfully, not 241', flush=True)
