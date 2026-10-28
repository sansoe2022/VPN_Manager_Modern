import base64
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import classic
import manager
import online

ANSI=re.compile(r'\x1b\[[0-9;]*m')


class Layout(unittest.TestCase):
    def test_colored_menu_columns_keep_the_original_width(self):
        left=[('19','ONLINE APP',True),('20','CHECKUSER',False)]
        right=[('28','TELEGRAM BOT',False),('34','RESELLER BOT',True)]
        output=classic.table(left,right,color=True)
        self.assertIn('\x1b[32m',output)
        self.assertIn('\x1b[31m',output)
        for line in ANSI.sub('',output).splitlines():
            self.assertEqual(len(line),47)
            self.assertEqual(line[24],'[')
        self.assertIn('ON',ANSI.sub('',output))
        self.assertIn('OFF',ANSI.sub('',output))

    def test_long_report_values_stay_readable_without_truncation(self):
        core=SimpleNamespace(collect=lambda:{'users':{'ssh':['a']}},users=lambda:['a'])
        ui=classic.Classic(core)
        password='long-password-'*8
        with patch.object(ui,'metadata',return_value=({'password':password,'limit':3},False,'2030-01-01 12:34',False)), \
             patch.object(classic.shutil,'get_terminal_size',return_value=__import__('os').terminal_size((47,24))), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            ui.report()
        lines=output.getvalue().splitlines()
        self.assertTrue(all(len(line)<=47 for line in lines))
        begin=next(index for index,line in enumerate(lines) if line.startswith('Password'))
        end=next(index for index,line in enumerate(lines) if line.startswith('Connections'))
        recovered=lines[begin].split(': ',1)[1]+''.join(line.strip() for line in lines[begin+1:end])
        self.assertEqual(recovered,password)
        self.assertIn('2030-01-01 12:34',output.getvalue())

    def test_port_and_link_status_require_live_listeners(self):
        config={**manager.DEFAULTS,'enabled':['online','openvpn','udp'],'endpoint':'vpn.example.com',
                'checkuser':True,'udp_port':36712}
        core=SimpleNamespace(SERVICES=manager.SERVICES)
        ui=classic.Classic(core)
        text='tcp LISTEN 0 128 0.0.0.0:81 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:36712 0.0.0.0:*'
        with patch.object(ui,'active',return_value=True):
            rows=ui.port_status(config,text)
            with contextlib.redirect_stdout(io.StringIO()) as output: ui.links(config,text)
        self.assertIn(('OpenVPN',1194,False),rows['tcp'])
        self.assertIn(('Online API',81,True),rows['tcp'])
        self.assertEqual(rows['udp'],[('Hysteria UDP',36712,True),('UDP hopping','10000-65000',True)])
        self.assertIn('http://vpn.example.com:81/checkuser',output.getvalue())
        self.assertIn('/server/online_app',output.getvalue())
        with patch.object(ui,'active',return_value=False),contextlib.redirect_stdout(io.StringIO()) as output:
            ui.links(config,text)
        self.assertNotIn('http://',output.getvalue())
        self.assertIn('OFF',output.getvalue())

    def test_checkuser_install_starts_service_without_opening_online_submenu(self):
        config={**manager.DEFAULTS,'endpoint':'vpn.example.com','enabled':[]}
        core=SimpleNamespace(load=lambda:config,SERVICES=manager.SERVICES,choose=lambda *args:'api',
                             configure=Mock(),save=Mock())
        ui=classic.Classic(core)
        with patch.object(ui,'service',side_effect=AssertionError('Opened wrong submenu')),contextlib.redirect_stdout(io.StringIO()) as output:
            ui.checkuser()
        core.configure.assert_called_once_with('online',config,81)
        self.assertTrue(config['checkuser'])
        self.assertIn('http://vpn.example.com:81/checkuser',output.getvalue())


class CheckUserHTTP(unittest.TestCase):
    def test_only_requested_account_fields_are_returned_after_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.json'; config.write_text('{"checkuser":true}')
            server=online.ThreadingHTTPServer(('127.0.0.1',0),online.Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            with patch.object(online,'CONFIG_PATH',config), \
                 patch.object(online.grp,'getgrnam',return_value=SimpleNamespace(gr_mem=['a'],gr_gid=12345)), \
                 patch.object(online.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=12345)), \
                 patch.object(online.accounts,'verify_password',return_value=True), \
                 patch.object(online.accounts,'load',return_value={'a':{'limit':3,'password':'never-publish-this'}}), \
                 patch.object(online.subprocess,'run',return_value=SimpleNamespace(stdout='a:$hash:0:0:0:0:0:20000:\n')), \
                 patch.object(online,'collect',side_effect=AssertionError('CheckUser should not depend on online totals')), \
                 contextlib.redirect_stderr(io.StringIO()):
                thread.start()
                try:
                    url=f'http://127.0.0.1:{server.server_port}/checkuser'
                    with self.assertRaises(HTTPError) as error: urlopen(url)
                    self.assertEqual(error.exception.code,401)
                    header='Basic '+base64.b64encode(b'a:1').decode()
                    with urlopen(Request(url,headers={'Authorization':header})) as response:
                        data=json.load(response)
                    self.assertEqual(data,{'username':'a','connection_limit':3,
                        'expire_date':(dt.date(1970,1,1)+dt.timedelta(days=20000)).isoformat()})
                    config.write_text('{"checkuser":false}')
                    with self.assertRaises(HTTPError) as error: urlopen(Request(url,headers={'Authorization':header}))
                    self.assertEqual(error.exception.code,404)
                finally: server.shutdown(); server.server_close(); thread.join()

if __name__=='__main__': unittest.main()
