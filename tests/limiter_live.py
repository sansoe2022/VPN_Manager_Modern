"""Real combined SSH/OpenVPN/UDP admission; disposable NET_ADMIN container only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import manager
import accounts
import admission
import udp_runtime

if os.geteuid() or not Path('/.dockerenv').exists():
    raise SystemExit('Run only in a disposable root NET_ADMIN container.')
shutil.copytree('/src/vpnmanager','/usr/local/lib/vpnmanager',dirs_exist_ok=True)
Path('/usr/local/lib/vpnmanager').chmod(0o755)
for path in Path('/usr/local/lib/vpnmanager').glob('*.py'): path.chmod(0o644)
manager.write('/usr/local/bin/vpnmanager','#!/bin/sh\nexec python3 /usr/local/lib/vpnmanager/manager.py "$@"\n',0o755)
Path('/dev/net').mkdir(exist_ok=True)
if not Path('/dev/net/tun').exists(): os.mknod('/dev/net/tun',0o20600,os.makedev(10,200))
Path('/run/openvpn-server').mkdir(exist_ok=True)
udp_runtime.BINARY.parent.mkdir(exist_ok=True,parents=True)
shutil.copy2('/tmp/hysteria-test',udp_runtime.BINARY); udp_runtime.BINARY.chmod(0o755)
real_run=manager.run

def run(*args,**kwargs):
    if args[0] in ('systemctl','sysctl'): return subprocess.CompletedProcess(args,0,'')
    return real_run(*args,**kwargs)

def start(name,config):
    config['enabled']=sorted(set(config['enabled'])|{name}); manager.save(config)

with patch.object(manager,'run',side_effect=run),patch.object(manager,'start',side_effect=start):
    manager.initialize()
    config=manager.load(); config.update(endpoint='localhost',limiter_enabled=True)
    manager.save(config)
    manager.create_user('a',1,secret='1',limit=1)
    manager.configure_ssh(config,2222)
    manager.configure('openvpn',config,1194)
    udp_runtime.configure(manager,config,36712)
    manager.export_client(config,'/tmp/limit.ovpn')
Path('/tmp/limit.ovpn').write_text(Path('/tmp/limit.ovpn').read_text().replace('remote localhost ', 'remote 127.0.0.1 '))
manager.write('/tmp/limit-auth','a\n1\n')
processes=[]
serial=0

def launch(args,label):
    global serial
    serial+=1
    path=Path(f'/tmp/limit-{label}-{serial}.log')
    with path.open('w') as output: process=subprocess.Popen(args,stdout=output,stderr=subprocess.STDOUT)
    processes.append(process)
    return process,path

def wait(check,message,timeout=12):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if check(): return
        time.sleep(.1)
    raise AssertionError(message)

def client(protocol,allowed=True):
    before=manager.collect()['users'][protocol].count('a')
    if protocol=='ssh':
        args=['sshpass','-p','1','ssh','-N','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','NumberOfPasswordPrompts=1','-p','2222','a@127.0.0.1']
    elif protocol=='openvpn':
        args=['openvpn','--config','/tmp/limit.ovpn','--auth-user-pass','/tmp/limit-auth','--route-noexec','--ifconfig-noexec','--connect-retry-max','1']
    else:
        # Distinct client relay addresses are unnecessary for the handshake test.
        manager.write('/tmp/limit-udp.json',json.dumps({'server':'127.0.0.1:36712','server_name':'localhost','auth_str':'a:1',
            'obfs':'svpn','ca':'/etc/vpnmanager/udp-ca.crt','up_mbps':10,'down_mbps':10,'quit_on_disconnect':True,
            'retry':0,'handshake_timeout':3,'idle_timeout':4,'socks5':{'listen':'127.0.0.1:0'}}))
        args=[str(udp_runtime.BINARY),'--no-check','client','-c','/tmp/limit-udp.json']
    process,path=launch(args,protocol)
    if allowed:
        if protocol=='openvpn':
            wait(lambda:'Initialization Sequence Completed' in path.read_text(), 'OpenVPN did not connect: '+str(path))
        else:
            wait(lambda:manager.collect()['users'][protocol].count('a') > before,protocol+' did not connect: '+str(path))
        assert process.poll() is None, path.read_text()
    else:
        wait(lambda:process.poll() is not None,protocol+' excess connection was not rejected: '+str(path))
        if protocol=='openvpn':
            assert 'AUTH_FAILED' in path.read_text() and 'Initialization Sequence Completed' not in path.read_text()
        else:
            assert process.returncode!=0,protocol+' excess connection returned success: '+path.read_text()
    return process

try:
    launch(['python3','/usr/local/lib/vpnmanager/admission.py','serve'],'gate')
    wait(lambda:Path(admission.SOCKET).exists(),'Admission socket absent')
    launch(['/usr/sbin/sshd','-D','-e','-f','/etc/vpnmanager/sshd_config'],'sshd')
    launch(['openvpn','--cd','/etc/openvpn/server','--config','vpnmanager.conf'],'server')
    launch(['python3','/usr/local/lib/vpnmanager/manager.py','serve-udp'],'hysteria')
    wait(lambda:manager.capture('ss','-H','-lun','sport','=','36712'),'UDP listener absent')
    for protocol in ('ssh','openvpn','udp'):
        primary=client(protocol)
        if protocol=='ssh':
            snapshot=admission.observed(manager)
            with admission.ledger() as rows:
                assert any(key.startswith('ssh:') and key in snapshot and admission.process(row['pid']) for key,row in rows.items()), 'PAM reservation does not identify the live SSH connection'
        for other in ('ssh','openvpn','udp'):
            client(other,allowed=False)
            assert primary.poll() is None,'Admission killed the existing '+protocol+' connection'
        print('PASS limit 1: '+protocol+' stays connected; extra SSH/OpenVPN/UDP are denied',flush=True)
        primary.terminate(); primary.wait(timeout=5)
        wait(lambda:manager.collect()['total']==0,'Disconnected session still counted',timeout=15)
        # OpenVPN uses a disconnect hook; allow its completed callback to release the claim.
        if protocol=='openvpn':
            wait(lambda:not any(key.startswith('openvpn:') for key in json.loads((admission.ROOT/'admission.json').read_text())),'OpenVPN slot was not released')
    accounts.update('a',limit=2)
    first=client('ssh'); second=client('udp')
    client('openvpn',allowed=False)
    second.terminate(); second.wait(timeout=5)
    wait(lambda:not udp_runtime.sessions(),'UDP slot did not clear',timeout=15)
    third=client('openvpn')
    assert first.poll() is None
    print('PASS mixed limit 2, preserved existing SSH, and released UDP slot reused by OpenVPN',flush=True)
    accounts.update('a',limit=1)
    manager.enforce_limits()
    wait(lambda:not any(key.startswith('openvpn:') for key in json.loads((admission.ROOT/'admission.json').read_text())), 'Lowered limit did not remove the newer OpenVPN connection')
    assert first.poll() is None,'Lowered limit removed the older SSH session'
    print('PASS lowered limit removes only newer OpenVPN and preserves older SSH',flush=True)
    config=manager.load(); config['limiter_enabled']=False; manager.save(config)
    extra=client('ssh')
    assert extra.poll() is None and first.poll() is None
    print('PASS limiter OFF allows another connection without restarting active sessions',flush=True)
    # Distribution administrators must bypass even a failed managed-account helper.
    manager.run('useradd','-m','-s','/bin/bash','admintest')
    manager.run('chpasswd','-c','SHA512',input='admintest:1\n')
    admin_server,admin_log=launch(['/usr/sbin/sshd','-D','-e','-f','/etc/ssh/sshd_config','-p','2223'],'admin-server')
    wait(lambda:manager.capture('ss','-H','-ltn','sport','=','2223'),'Admin SSH listener absent')
    helper=Path('/usr/local/lib/vpnmanager/admission.py')
    missing=helper.with_suffix('.disabled')
    helper.rename(missing)
    try:
        admin,_=launch(['sshpass','-p','1','ssh','-N','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-p','2223','admintest@127.0.0.1'],'admin')
        wait(lambda:'Accepted' in admin_log.read_text() and 'admintest' in admin_log.read_text(),'Unmanaged administrator was denied by managed PAM hook')
        assert admin.poll() is None
    finally:
        missing.rename(helper)
    print('PASS unmanaged administrator SSH bypasses even a failed limiter helper',flush=True)

except BaseException:
    for path in sorted(Path('/tmp').glob('limit-*.log')):
        print(str(path)+'\n'+path.read_text(),flush=True)
    ledger=admission.ROOT/'admission.json'
    if ledger.exists(): print('Ledger: '+ledger.read_text())
    print(manager.capture('ps','-eo','pid=,ppid=,args='))
    raise
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
