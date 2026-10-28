import collections
import contextlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpnmanager'))
import accounts
import classic
import dropbear_state
import manager
import private_backup
import telegram_bot


class Navigation(unittest.TestCase):
    def test_original_numbering_and_removed_v2ray(self):
        first = classic.MAIN_LEFT + classic.MAIN_RIGHT
        second = classic.MORE_LEFT + classic.MORE_RIGHT
        self.assertEqual({int(key) for key, _ in first}, set(range(23)))
        self.assertEqual({int(key) for key, _ in second}, {0, *range(23, 36)})
        self.assertEqual({int(key) for key, _ in classic.CONNECTIONS}, set(range(10)))
        self.assertNotIn('V2RAY', classic.table(first, second))
        self.assertIn('[01] CREATE USER', classic.table(classic.MAIN_LEFT, classic.MAIN_RIGHT))
        self.assertIn('[34] RESELLER BOT', classic.table(classic.MORE_LEFT, classic.MORE_RIGHT))

    def test_10_00_returns_to_main_then_more_and_back(self):
        ui = classic.Classic(manager)
        ui.color = False
        with patch.object(ui, 'header') as header, patch.object(ui, 'pause') as pause, \
             patch('builtins.input', side_effect=['10', '00', '22', '35', '00']), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            ui.menu()
        self.assertEqual(header.call_count, 5)
        pause.assert_not_called()
        self.assertEqual(output.getvalue().count('[01] CREATE USER'), 3)
        self.assertIn('[00] BACK TO MAIN MENU', output.getvalue())

    def test_selecting_a_feature_clears_the_screen_before_its_page(self):
        ui = classic.Classic(manager)
        order = []
        with patch.object(ui, 'clear', side_effect=lambda: order.append('clear')), \
             patch.object(ui, 'report', side_effect=lambda: order.append('report')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            ui.feature('09')
        self.assertEqual(order, ['clear', 'report'])
        self.assertIn('USER REPORT', output.getvalue())

    def test_invalid_connection_selection_never_exits(self):
        ui = classic.Classic(manager)
        with patch.object(ui, 'header'), patch('builtins.input', side_effect=['99', 'bad', '00']), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            ui.connections()
        self.assertEqual(output.getvalue().count('Invalid option.'), 2)

    def test_create_prompts_visible_password_immediately_after_username(self):
        core = SimpleNamespace(create_user=Mock(), validate_password=manager.validate_password)
        ui = classic.Classic(core)
        with patch('builtins.input', side_effect=['alice', 'Visible-password-47', '30', '2']) as prompt, \
             contextlib.redirect_stdout(io.StringIO()):
            ui.create()
        self.assertEqual(prompt.call_args_list[0].args, ('Username: ',))
        self.assertEqual(prompt.call_args_list[1].args, ('Password (visible): ',))
        self.assertIn('Validity', prompt.call_args_list[2].args[0])
        self.assertIn('connection limit', prompt.call_args_list[3].args[0])
        core.create_user.assert_called_once_with('alice', 30, secret='Visible-password-47', limit=2)

    def test_trial_sets_minute_expiry_and_sufficient_pam_days(self):
        core = SimpleNamespace(create_user=Mock(), validate_password=manager.validate_password)
        ui = classic.Classic(core)
        with patch('builtins.input', side_effect=['trialuser', 'Visible-password-47', '2880', '2']), \
             patch.object(accounts, 'update') as update, patch.object(classic.time, 'time', return_value=1000), \
             contextlib.redirect_stdout(io.StringIO()):
            ui.create(True)
        core.create_user.assert_called_once_with('trialuser', 4, secret='Visible-password-47', limit=2)
        update.assert_called_once_with('trialuser', expires_at=173800, trial=True)


class AccountState(unittest.TestCase):
    def test_metadata_survives_updates_and_delete(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(accounts, 'PATH', Path(directory) / 'accounts.json'):
            accounts.update('alice', limit=2)
            accounts.update('alice', owner=10)
            self.assertEqual(accounts.load()['alice']['limit'], 2)
            self.assertEqual((accounts.PATH.stat().st_mode & 0o777), 0o600)
            accounts.remove('alice')
            self.assertEqual(accounts.load(), {})

    def test_expiry_boundary_and_daily_account_expiry(self):
        fields = ['alice', '$hash', '', '', '', '', '', '', '']
        self.assertFalse(accounts.expired({'expires_at': 1001}, fields, 1000))
        self.assertTrue(accounts.expired({'expires_at': 1000}, fields, 1000))
        fields[7] = '1'
        self.assertTrue(accounts.expired({}, fields, 86400))

    def test_combined_protocol_limits_remove_only_newest_excess_session(self):
        gate = manager.admission
        rows = {'ssh:11': {'user':'alice','created':1},
                'openvpn:127.0.0.1:1234': {'user':'alice','created':2},
                'dropbear:12': {'user':'alice','created':3}}
        with patch.object(manager, 'load', return_value={'limiter_enabled':True}), \
             patch.object(gate, 'observed', return_value={'ssh:11':'alice','dropbear:12':'alice','ssh:13':'bob'}), \
             patch.object(gate, 'ledger', return_value=contextlib.nullcontext(rows)), patch.object(gate, 'prune'), \
             patch.object(accounts, 'load', return_value={'alice': {'limit':2}, 'bob': {'limit':1}}), \
             patch.object(gate.os, 'kill') as kill, patch.object(manager, 'disconnect') as disconnect:
            manager.enforce_limits()
        kill.assert_called_once_with(12, gate.signal.SIGTERM)
        disconnect.assert_not_called()

    def test_dropbear_pid_reuse_cannot_count_an_old_login(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dropbear_state, 'PATH', Path(directory) / 'sessions.json'):
            dropbear_state.save({'123': {'user': 'alice', 'start': 'old'}})
            with patch.object(dropbear_state, 'identity', return_value='new'):
                self.assertEqual(dropbear_state.sessions(), [])
            with patch.object(dropbear_state, 'identity', return_value='old'):
                self.assertEqual(dropbear_state.sessions(), [('alice', 123)])

    def test_backup_rejects_paths_and_symlinks(self):
        for name, kind in [('../etc/shadow', tarfile.REGTYPE), ('/etc/shadow', tarfile.REGTYPE),
                           ('config/secret', tarfile.SYMTYPE), ('openvpn/other.conf', tarfile.REGTYPE)]:
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.type = kind
                archive = Mock()
                archive.getmembers.return_value = [member]
                with self.assertRaises(ValueError):
                    private_backup.validate_members(archive)


class BotPermissions(unittest.TestCase):
    def bot(self, role='admin', resellers=None):
        bot = object.__new__(telegram_bot.Bot)
        bot.m = SimpleNamespace(run=Mock(), create_user=Mock(), users=Mock(return_value=['alice']), managed=Mock())
        bot.role = role
        bot.data = {'owner': 1, 'resellers': resellers or {}}
        return bot

    def test_unknown_sender_cannot_create_accounts(self):
        bot = self.bot()
        self.assertIn('Access denied', bot.command(9, '/create mallory Password-123 30 1'))
        bot.m.create_user.assert_not_called()
        bot.m.run.assert_not_called()

    def test_reseller_cannot_remove_another_resellers_account(self):
        bot = self.bot('reseller', {'9': 5})
        with patch.object(accounts, 'load', return_value={'alice': {'owner': 10}}):
            with self.assertRaises(ValueError):
                bot.command(9, '/remove alice')
        bot.m.run.assert_not_called()

    def test_reseller_quota_counts_existing_owned_accounts(self):
        bot = self.bot('reseller', {'9': 1})
        with patch.object(accounts, 'load', return_value={'alice': {'owner': 9}}):
            with self.assertRaises(ValueError):
                bot.command(9, '/create second Password-123 30 1')
        bot.m.create_user.assert_not_called()

    def test_trial_reuse_is_rejected_without_creating_account(self):
        bot = self.bot('trial')
        bot.data['claims'] = {'9': 1000}
        with patch.object(telegram_bot.time, 'time', return_value=1100):
            with self.assertRaises(ValueError):
                bot.command(9, '/trial')
        bot.m.create_user.assert_not_called()


if __name__ == '__main__':
    unittest.main()
