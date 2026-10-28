"""Two-container full migration; optional binaries/database fixtures are not real x-ui deployments."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import accounts
import backup_crypto
import extras
import manager
import private_backup
import udp_runtime

if os.geteuid() or not Path('/.dockerenv').exists():
    raise SystemExit('Use a disposable root container.')
mode=sys.argv[1]
shutil.copytree('/src/vpnmanager','/usr/local/lib/vpnmanager',dirs_exist_ok=True)
Path('/dev/net').mkdir(exist_ok=True)
if not Path('/dev/net/tun').exists(): os.mknod('/dev/net/tun',0o20600,os.makedev(10,200))
Path('/run/openvpn-server').mkdir(exist_ok=True)
real_run=manager.run
calls=[]
def run(*args,**kwargs):
    calls.append(args)
    if args[0] in ('systemctl','sysctl'): return subprocess.CompletedProcess(args,0,'')
    return real_run(*args,**kwargs)
def start(name,config):
    config['enabled']=sorted(set(config['enabled'])|{name}); manager.save(config)
password='migration-test-password-only'
paths=['/etc/openvpn/server/vpnmanager-server.key','/etc/vpnmanager/tls.key','/etc/vpnmanager/udp-server.key',
       '/etc/vpnmanager/ssh_host_ed25519_key','/etc/dropbear/dropbear_rsa_host_key','/etc/vpnmanager/udp-ca.key']
with patch.object(manager,'run',side_effect=run),patch.object(manager,'start',side_effect=start),patch.object(extras,'package'):
    manager.initialize()
    if mode=='export':
        config=manager.load(); config['endpoint']='localhost'
        manager.create_user('migrated',7,secret='1',limit=3)
        manager.configure_proxy(config,8880,['openvpn']); manager.configure_proxy(config,2086,['ssh'])
        config['tls_backend']='openvpn'; manager.configure('tls',config,443)
        manager.configure('squid',config,3128); manager.configure('online',config,81)
        extras.dropbear(manager,config,109)
        udp_runtime.BINARY.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2('/tmp/hysteria-test',udp_runtime.BINARY); udp_runtime.BINARY.chmod(0o755)
        udp_runtime.configure(manager,config,36712)
        xui=Path('/usr/local/x-ui'); xui.mkdir(parents=True,exist_ok=True)
        manager.write(xui/'x-ui','#!/bin/sh\nexit 0\n',0o755)
        manager.write('/etc/systemd/system/x-ui.service','[Service]\nExecStart=/usr/local/x-ui/x-ui\n',0o644)
        Path('/etc/x-ui').mkdir(exist_ok=True)
        with sqlite3.connect('/etc/x-ui/x-ui.db') as db:
            db.execute('CREATE TABLE settings (name TEXT,value TEXT)')
            db.execute('INSERT INTO settings VALUES (?,?)',('fixture','restored'))
        config['enabled']=sorted(set(config['enabled'])|{'xui'}); manager.save(config)
        archive=private_backup.create(manager)
        with __import__('tarfile').open(archive) as bundle:
            names=bundle.getnames()
            for name in ('source/manager.py','source/bin/hysteria','xui-config/x-ui.db','units/vpnmanager-tunnel.service','config/sshd_config'):
                assert name in names,name
        expected={'keys':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in paths},
                  'udp_ca':hashlib.sha256(Path('/etc/vpnmanager/udp-ca.crt').read_bytes()).hexdigest(),'enabled':config['enabled']}
        Path('/transfer/expected.json').write_text(json.dumps(expected))
        backup_crypto.encrypt(archive,'/transfer/backup.vpnbak',password)
        print('PASS full source/config/key/account/optional-database backup and encryption',flush=True)
    elif mode=='restore':
        root_before=manager.capture('getent','shadow','root')
        class Handler(SimpleHTTPRequestHandler):
            def __init__(self,*args,**kwargs): super().__init__(*args,directory='/transfer',**kwargs)
            def log_message(self,*args): pass
        web=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=web.serve_forever,daemon=True); thread.start()
        try:
            manager.write('/tmp/restore-password', password)
            with patch.object(sys, 'argv', ['vpnmanager', 'restore', f'http://127.0.0.1:{web.server_port}/backup.vpnbak',
                                          '--password-file', '/tmp/restore-password', '--endpoint', '127.0.0.2']):
                manager.main()
        finally: web.shutdown(); web.server_close(); thread.join()
        expected=json.loads(Path('/transfer/expected.json').read_text())
        assert {name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in expected['keys']}==expected['keys']
        if 'udp_ca' in expected:
            assert hashlib.sha256(Path('/etc/vpnmanager/udp-ca.crt').read_bytes()).hexdigest()==expected['udp_ca']
        assert accounts.verify_password('migrated','1')
        assert accounts.load()['migrated']['password']=='1' and accounts.load()['migrated']['limit']==3
        assert manager.load()['endpoint']=='127.0.0.2'
        assert manager.load()['udp_server_name']=='127.0.0.2'
        subprocess.run(['openssl','x509','-in','/etc/vpnmanager/udp-server.crt','-noout','-checkip','127.0.0.2'],check=True)
        assert set(manager.load()['enabled'])==set(expected['enabled'])
        assert manager.capture('getent','shadow','root')==root_before
        with sqlite3.connect('/etc/x-ui/x-ui.db') as db: assert db.execute('SELECT value FROM settings').fetchone()[0]=='restored'
        assert any(args[:4]==('systemctl','enable','--now','x-ui') for args in calls)
        assert Path('/usr/local/bin/menu').is_symlink()
        print('PASS restore by URL on a fresh server: all service configs/keys, users/passwords, source/binaries and x-ui SQLite fixture; admin shadow unchanged',flush=True)
    else: raise ValueError('Choose export or restore')
if mode=='restore':
    subprocess.run(['python3','/src/tests/openvpn_live.py'],check=True)
    subprocess.run(['python3','/src/tests/udp_live.py'],check=True,env={**os.environ,'UDP_TEST_ENDPOINT':'127.0.0.2'})
    print('PASS real restored SSH, OpenVPN/WebSocket/SSL and UDP client sessions',flush=True)
