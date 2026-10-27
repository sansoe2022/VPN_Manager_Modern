"""Readable English Telegram management, trial and reseller bots.

Tokens and credentials are never logged. Commands run only in private chats.
"""
import getpass
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import accounts

ROLES = ('admin', 'trial', 'reseller')


def config_path(role):
    if role not in ROLES:
        raise ValueError('Unknown bot role.')
    return Path('/etc/vpnmanager/bot-' + role + '.json')


def configure(m, role):
    path = config_path(role)
    action = m.choose(role.upper() + ' BOT', [('1', 'Configure / start bot', 'setup'),
        ('2', 'Stop bot', 'stop'), ('3', 'Restart bot', 'restart'), ('0', 'Back', None)])
    if action is None:
        return
    unit = 'vpnmanager-bot-' + role
    if action in ('stop', 'restart'):
        m.run('systemctl', 'disable' if action == 'stop' else 'restart', *(['--now'] if action == 'stop' else []), unit)
        return
    token = getpass.getpass('Telegram bot token from @BotFather (hidden): ').strip()
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]{20,}', token):
        raise ValueError('Invalid Telegram bot token format.')
    owner = int(input('Your Telegram numeric user ID: '))
    if owner <= 0:
        raise ValueError('Use a positive Telegram user ID.')
    minutes = int(input('Trial validity in minutes [60]: ') or '60')
    if not 1 <= minutes <= 10080:
        raise ValueError('Choose 1-10080 minutes.')
    data = {'token': token, 'owner': owner, 'trial_minutes': minutes}
    if path.exists():
        previous = json.loads(path.read_text())
        data['resellers'] = previous.get('resellers', {})
        data['claims'] = previous.get('claims', {})
    m.write(path, json.dumps(data, indent=2) + '\n')
    m.service_unit(unit, '/usr/local/bin/vpnmanager serve-bot ' + role,
                   'ProtectSystem=false\nProtectHome=false')
    m.run('systemctl', 'daemon-reload')
    m.run('systemctl', 'enable', '--now', unit)
    m.run('systemctl', 'restart', unit)
    print('Bot started. Open its private Telegram chat and send /start.')


class Bot:
    def __init__(self, m, role):
        self.m = m
        self.role = role
        self.path = config_path(role)
        self.data = json.loads(self.path.read_text())

    def api(self, method, payload):
        request = Request('https://api.telegram.org/bot' + self.data['token'] + '/' + method,
                          data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
        with urlopen(request, timeout=40) as response:
            data = json.load(response)
        if not data.get('ok'):
            raise ValueError('Telegram could not complete the request.')
        return data['result']

    def persist(self):
        self.m.write(self.path, json.dumps(self.data, indent=2) + '\n')

    def owner(self, sender):
        return sender == self.data['owner']

    def owned(self, sender, username):
        self.m.managed(username)
        if not self.owner(sender) and accounts.load().get(username, {}).get('owner') != sender:
            raise ValueError('You can manage only your own accounts.')

    def allowance(self, sender):
        if self.owner(sender):
            return
        quota = self.data.get('resellers', {}).get(str(sender), 0)
        active = set(self.m.users())
        used = sum(record.get('owner') == sender for name, record in accounts.load().items() if name in active)
        if used >= quota:
            raise ValueError('No reseller account slots are available. Contact the owner.')

    def trial(self, sender):
        claims = self.data.setdefault('claims', {})
        if not self.owner(sender) and time.time() - claims.get(str(sender), 0) < 86400:
            raise ValueError('One trial is available per Telegram user every 24 hours.')
        name, secret = 't' + secrets.token_hex(5), secrets.token_urlsafe(12)
        minutes = self.data.get('trial_minutes', 60)
        self.m.create_user(name, 8, secret=secret)
        accounts.update(name, owner=sender, trial=True, expires_at=int(time.time()) + minutes * 60)
        claims[str(sender)] = int(time.time())
        self.persist()
        return f'Trial account created.\nUsername: {name}\nPassword: {secret}\nValidity: {minutes} minutes\nServer: {self.m.load().get("endpoint") or "Ask the owner for the server address."}'

    def command(self, sender, text):
        parts = text.split()
        if not parts:
            return 'Send /help to see the commands.'
        command = parts[0].split('@')[0].lower()
        if command in ('/start', '/menu', '/help'):
            if self.role == 'trial' and not self.owner(sender):
                return 'Welcome. Send /trial to create a trial account.'
            return ('SSHPlus Manager\n/status\n/users\n/create USER PASSWORD DAYS LIMIT\n/trial\n'
                    '/remove USER\n/password USER PASSWORD\n/renew USER DAYS\n/limit USER LIMIT\n'
                    '/lock USER\n/unlock USER\nOwner: /allow TELEGRAM_ID QUOTA, /revoke TELEGRAM_ID')
        if self.role == 'trial' and command == '/trial':
            return self.trial(sender)
        allowed = self.owner(sender) or (self.role == 'reseller' and self.data.get('resellers', {}).get(str(sender), 0) > 0)
        if not allowed:
            return 'Access denied. Ask the bot owner to authorize your Telegram user ID.'
        if command == '/status':
            count = self.m.collect()
            return 'Online sessions: ' + str(count['total'])
        if command == '/users':
            names = self.m.users()
            if not self.owner(sender):
                names = [name for name in names if accounts.load().get(name, {}).get('owner') == sender]
            return 'Accounts:\n' + ('\n'.join(sorted(names)) or '(none)')
        if command == '/trial':
            self.allowance(sender)
            return self.trial(sender)
        if command == '/create' and len(parts) == 5:
            self.allowance(sender)
            limit = int(parts[4])
            if not 1 <= limit <= 1000:
                raise ValueError('Connection limit must be 1-1000.')
            self.m.create_user(parts[1], int(parts[3]), secret=parts[2], limit=limit)
            accounts.update(parts[1], owner=sender)
            return 'Account created: ' + parts[1]
        if command in ('/allow', '/revoke') and self.owner(sender):
            if len(parts) != (3 if command == '/allow' else 2):
                raise ValueError('Use /allow TELEGRAM_ID QUOTA or /revoke TELEGRAM_ID.')
            target = int(parts[1])
            quota = int(parts[2]) if command == '/allow' else 0
            if target <= 0 or not 0 <= quota <= 10000:
                raise ValueError('Invalid user ID or quota.')
            self.data.setdefault('resellers', {})[str(target)] = quota
            self.persist()
            return 'Reseller permission updated.'
        if len(parts) < 2:
            return 'Invalid command. Send /help.'
        username = parts[1]
        self.owned(sender, username)
        if command == '/remove' and len(parts) == 2:
            self.m.disconnect(username)
            self.m.run('userdel', username)
            accounts.remove(username)
        elif command == '/password' and len(parts) == 3:
            secret = parts[2]
            if len(secret) < 10 or any(char in secret for char in ':\r\n'):
                raise ValueError('Use a password of at least 10 characters without colons or newlines.')
            self.m.run('chpasswd', input=f'{username}:{secret}\n')
        elif command == '/renew' and len(parts) == 3:
            self.m.expiry(username, int(parts[2]))
            self.m.run('usermod', '-U', username)
        elif command == '/limit' and len(parts) == 3:
            limit = int(parts[2])
            if not 1 <= limit <= 1000:
                raise ValueError('Connection limit must be 1-1000.')
            accounts.update(username, limit=limit)
        elif command in ('/lock', '/unlock') and len(parts) == 2:
            self.m.run('usermod', '-L' if command == '/lock' else '-U', username)
            if command == '/lock':
                self.m.disconnect(username)
        else:
            return 'Invalid command. Send /help.'
        return 'Updated: ' + username

    def run(self):
        offset_path = self.m.STATE / ('bot-offset-' + self.role)
        offset = int(offset_path.read_text()) if offset_path.exists() else 0
        while True:
            try:
                updates = self.api('getUpdates', {'offset': offset, 'timeout': 25, 'allowed_updates': ['message']})
                for update in updates:
                    offset = update['update_id'] + 1
                    self.m.write(offset_path, str(offset))
                    message = update.get('message', {})
                    sender = message.get('from', {}).get('id')
                    chat = message.get('chat', {})
                    if chat.get('type') != 'private' or sender != chat.get('id'):
                        continue
                    try:
                        reply = self.command(sender, message.get('text', ''))
                    except ValueError as error:
                        reply = str(error)
                    except (OSError, subprocess.SubprocessError):
                        reply = 'The server could not complete that action. Ask the owner to check service logs.'
                    self.api('sendMessage', {'chat_id': sender, 'text': reply[:4000]})
            except (URLError, HTTPError, OSError, ValueError, KeyError):
                # Never print exception URLs: they can contain the token.
                print('Bot request failed; retrying shortly.', flush=True)
                time.sleep(5)


def serve(m, role):
    Bot(m, role).run()
