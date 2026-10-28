from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vpnmanager'))
import login_banner

class BannerOptions(unittest.TestCase):
    def test_multiline_banner_cannot_add_server_directives_or_push_options(self):
        option=login_banner.openvpn_option('Hello, users\nroute 0.0.0.0 0.0.0.0')
        self.assertEqual(len(option.splitlines()),1)
        self.assertNotIn(',',option)
        self.assertIn('Hello&#44; users route',option)
        self.assertEqual(login_banner.openvpn_option(''), '')
        with self.assertRaises(ValueError): login_banner.openvpn_option('x\x00y')
        with self.assertRaises(ValueError): login_banner.openvpn_option('x'*1801)
