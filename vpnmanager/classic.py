"""Plain-source English version of the two-page SSHPlus menu."""
import collections
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import textwrap

import accounts
import extras
import proxy_config

MAIN_LEFT = [('01', 'CREATE USER'), ('02', 'CREATE TRIAL USER'), ('03', 'REMOVE USER'),
             ('04', 'ONLINE MONITOR'), ('05', 'CHANGE EXPIRY'), ('06', 'CHANGE LIMIT'),
             ('07', 'CHANGE PASSWORD'), ('08', 'REMOVE EXPIRED'), ('09', 'USER REPORT'),
             ('10', 'CONNECTION MODE'), ('00', 'EXIT')]
MAIN_RIGHT = [('11', 'SPEED TEST'), ('12', 'BANNER'), ('13', 'TRAFFIC'), ('14', 'OPTIMIZE'),
              ('15', 'BACKUP'), ('16', 'VIRTUAL MEMORY'), ('17', 'LIMITER'),
              ('18', 'BADVPN PRO'), ('19', 'ONLINE APP'), ('20', 'CHECKUSER'),
              ('21', 'VPS INFO'), ('22', 'MORE >>>')]
MORE_LEFT = [('23', 'ADD HOST'), ('24', 'REMOVE HOST'), ('25', 'REBOOT SYSTEM'),
             ('26', 'RESTART SERVICES'), ('27', 'BLOCK TORRENT'), ('28', 'TELEGRAM BOT'),
             ('29', 'TRIAL BOT')]
MORE_RIGHT = [('30', 'ROOT PASSWORD'), ('31', 'AUTO EXECUTION'), ('32', 'UPDATE SCRIPT'),
              ('33', 'REMOVE SCRIPT'), ('34', 'RESELLER BOT'), ('35', 'BACK <<<'), ('00', 'EXIT <<<')]
CONNECTIONS = [('01', 'OPENSSH'), ('02', 'SQUID PROXY'), ('03', 'DROPBEAR'),
               ('04', 'OPENVPN'), ('05', 'PROXY / WEBSOCKET'), ('06', 'SSL TUNNEL'),
               ('07', 'SSLH MULTIPLEX'), ('08', 'X-UI PANEL'), ('09', 'UDP / HYSTERIA'), ('00', 'BACK TO MAIN MENU')]


def choice(value):
    return value.strip().lstrip('0') or '0'


def listening_ports(output):
    ports = {'tcp': set(), 'udp': set()}
    for row in output.splitlines():
        fields = row.split()
        if len(fields) >= 5 and fields[0] in ports:
            value = fields[4].rsplit(':', 1)[-1]
            if value.isdigit():
                ports[fields[0]].add(int(value))
    return ports


def connection_ports(config, output):
    """Intersect real listeners with ports configured in Connection Mode."""
    allowed = {int(config[name + '_port']) for name in
               ('squid', 'dropbear', 'openvpn', 'tls', 'sslh', 'xui')
               if name in config.get('enabled', []) and config.get(name + '_port')}
    allowed.update(entry['port'] for entry in proxy_config.listeners(config))
    if config.get('ssh_bind') and config['ssh_bind'] not in ('127.0.0.1', '::1'):
        allowed.add(int(config['ssh_port']))
    listeners = listening_ports(output)
    udp = {config['udp_port']} if 'udp' in config.get('enabled', []) and config.get('udp_port') else set()
    return {'tcp': listeners['tcp'] & allowed, 'udp': listeners['udp'] & udp}


def connection_services(config, output):
    """Describe only configured Connection Mode listeners, using their backend roles."""
    actual = connection_ports(config, output)
    result = {'tcp': [], 'udp': []}
    if config.get('udp_port') in actual['udp']:
        result['udp'].append(('Hysteria UDP', config['udp_port']))
    labels = {'squid': 'Squid Proxy', 'dropbear': 'Dropbear SSH', 'openvpn': 'OpenVPN',
              'sslh': 'SSLH', 'xui': 'X-UI Panel'}
    for name, label in labels.items():
        number = config.get(name + '_port')
        if name in config.get('enabled', []) and number in actual['tcp']:
            result['tcp'].append((label, number))
    if config.get('ssh_port') in actual['tcp'] and config.get('ssh_bind') not in (None, '127.0.0.1', '::1'):
        result['tcp'].append(('OpenSSH', config['ssh_port']))
    for entry in proxy_config.listeners(config):
        if entry['port'] in actual['tcp']:
            result['tcp'].append((proxy_config.label(entry), entry['port']))
    if 'tls' in config.get('enabled', []) and config.get('tls_port') in actual['tcp']:
        backend = config.get('tls_backend', 'tunnel')
        label = {'openvpn': 'OpenVPN SSL', 'ssh': 'SSH SSL', 'tunnel': 'WebSocket SSL'}[backend]
        result['tcp'].append((label, config['tls_port']))
    return result


def table(left, right, color=False):
    def item(entry):
        number, label = entry[:2]
        running = entry[2] if len(entry) > 2 else None
        width = 14 if running is not None else 18
        body = f'{label[:width]:<{width}}'
        if running is not None:
            state = f'{"ON" if running else "OFF":>3}'
            body += ' ' + (f'\033[{32 if running else 31}m{state}\033[0m' if color else state)
        if color:
            return f'\033[31m[\033[36m{number}\033[31m] \033[33m{body}\033[0m'
        return f'[{number}] {body}'
    lines = []
    for index in range(max(len(left), len(right))):
        first = item(left[index]) if index < len(left) else ' ' * 23
        second = item(right[index]) if index < len(right) else ''
        lines.append(first + ' ' + second)
    return '\n'.join(lines)


class Classic:
    def __init__(self, core):
        self.m = core
        self.color = sys.stdout.isatty() and 'NO_COLOR' not in os.environ
        self.removed = False
        self.last_cpu = None
        self._active = {}

    def paint(self, text, code):
        return f'\033[{code}m{text}\033[0m' if self.color else text

    def state(self, running):
        return self.paint('ON' if running else 'OFF', '32' if running else '31')

    def field(self, label, value):
        prefix = f'{label:<11}: '
        width = min(47, max(32, shutil.get_terminal_size((47, 24)).columns))
        text = ''.join(char if char.isprintable() else f'\\x{ord(char):02x}' for char in str(value))
        print(textwrap.fill(text, width=width, initial_indent=prefix,
                            subsequent_indent=' ' * len(prefix), break_long_words=True,
                            break_on_hyphens=False, replace_whitespace=False, drop_whitespace=False))

    def api_url(self, config, path):
        host = config.get('endpoint', '')
        if not host:
            return '(set server IP/domain first)'
        if ':' in host:
            host = '[' + host.strip('[]') + ']'
        return f'http://{host}:{config["online_port"]}{path}'

    def port_status(self, config, output):
        actual = listening_ports(output)
        result = {'tcp': [], 'udp': []}
        names = [('openvpn', 'OpenVPN'), ('squid', 'Squid Proxy'), ('dropbear', 'Dropbear SSH'),
                 ('sslh', 'SSLH'), ('xui', 'X-UI Panel'), ('online', 'Online API')]
        for name, label in names:
            number = config.get(name + '_port')
            if number:
                on = name in config['enabled'] and number in actual['tcp'] and self.active(self.m.SERVICES[name])
                result['tcp'].append((label, number, on))
        if config.get('ssh_bind') not in (None, '127.0.0.1', '::1'):
            number = config['ssh_port']
            result['tcp'].append(('OpenSSH', number, number in actual['tcp'] and self.active('vpnmanager-sshd')))
        for entry in proxy_config.listeners(config, configured=True):
            on = 'tunnel' in config['enabled'] and entry['port'] in actual['tcp'] and self.active(self.m.SERVICES['tunnel'])
            result['tcp'].append((proxy_config.label(entry), entry['port'], on))
        if config.get('tls_port'):
            number = config['tls_port']
            label = {'openvpn': 'OpenVPN SSL', 'ssh': 'SSH SSL', 'tunnel': 'WebSocket SSL'}.get(config.get('tls_backend'), 'SSL Tunnel')
            on = 'tls' in config['enabled'] and number in actual['tcp'] and self.active(self.m.SERVICES['tls'])
            result['tcp'].append((label, number, on))
        number = config.get('udp_port', 36712)
        on = 'udp' in config['enabled'] and number in actual['udp'] and self.active(self.m.SERVICES['udp'])
        result['udp'].append(('Hysteria UDP', number, on))
        if config.get('udp_port'):
            result['udp'].append(('UDP hopping', config.get('udp_port_range', '10000-65000'), on))
        return result

    def links(self, config, output):
        print(self.paint('API Links:', '36'))
        running = ('online' in config['enabled'] and config['online_port'] in listening_ports(output)['tcp']
                   and self.active(self.m.SERVICES['online']))
        for label, path, on in [('Online', '/server/online', running),
                                ('Online App', '/server/online_app', running),
                                ('CheckUser', '/checkuser', running and config.get('checkuser', False))]:
            print(f'  {label:<24}' + self.state(on))
            if on:
                # Keep each URL on its own logical line so terminal auto-wrap remains copyable.
                print(self.api_url(config, path))

    def clear(self):
        if sys.stdout.isatty():
            print('\033[2J\033[H\033[3J', end='', flush=True)

    def page(self, title):
        self.clear()
        print(self.paint('=' * 47, '36'))
        print(self.paint(f'{title:^47}', '44;97'))
        print(self.paint('=' * 47, '36'))

    def pause(self):
        input('\nPress Enter to return: ')

    def metadata(self, username):
        fields = self.m.capture('getent', 'shadow', username).split(':')
        record = accounts.load().get(username, {})
        expired = accounts.expired(record, fields)
        if record.get('expires_at'):
            date = dt.datetime.fromtimestamp(record['expires_at']).strftime('%Y-%m-%d %H:%M')
        elif fields[7]:
            date = (dt.date(1970, 1, 1) + dt.timedelta(days=int(fields[7]))).isoformat()
        else:
            date = 'Never'
        return record, expired, date, fields[1].startswith(('!', '*'))

    def header(self, title='VPN Manager Modern | make with Ai by sansoe'):
        self._active = {}
        self.clear()
        line = '=' * 47
        print(self.paint(line, '36'))
        print(self.paint(f'{title:^47}', '41;97'))
        try:
            release = dict(row.split('=', 1) for row in Path('/etc/os-release').read_text().splitlines() if '=' in row)
            osname = release.get('ID', 'Linux').strip('"').title() + ' ' + release.get('VERSION_ID', '').strip('"')
            memory = dict((row.split(':')[0], int(row.split()[1])) for row in Path('/proc/meminfo').read_text().splitlines())
            cpu = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
            cpu_total, cpu_idle = sum(cpu[:8]), cpu[3] + cpu[4]
            previous_total, previous_idle = self.last_cpu or (0, 0)
            cpu_used = 100 * (1 - (cpu_idle - previous_idle) / max(1, cpu_total - previous_total))
            self.last_cpu = (cpu_total, cpu_idle)
            total = memory['MemTotal'] / 1024 ** 2
            used = 100 * (1 - memory.get('MemAvailable', memory['MemFree']) / memory['MemTotal'])
            online = self.m.collect()['total']
            names = self.m.users()
            expired = sum(self.metadata(name)[1] for name in names)
            print(self.paint(f'{"SYSTEM":<16}{"RAM MEMORY":<16}PROCESSOR', '36'))
            print(f'{osname[:15]:<16}{"Total:%.2fGiB" % total:<16}Cores: {os.cpu_count()}')
            print(f'{dt.datetime.now().strftime("%H:%M:%S"):<16}{"Used: %.1f%%" % used:<16}Used: {cpu_used:.1f}%')
            print(self.paint('-' * 47, '36'))
            print(f'{"Online: " + str(online):<16}{"Expired: " + str(expired):<16}Total: {len(names)}')
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            print('System statistics are temporarily unavailable.')
        try:
            config = self.m.load()
            output = self.m.capture('ss', '-H', '-lntu')
            ports = self.port_status(config, output)
            for protocol in ('tcp', 'udp'):
                print(self.paint(protocol.upper() + ' Ports:' + ('' if ports[protocol] else ' (none)'), '36'))
                for label, number, running in ports[protocol]:
                    print(f'  {label:<24}{number:>5} ' + self.state(running))
            self.links(config, output)
        except (OSError, subprocess.SubprocessError):
            print('Listening ports: unavailable')
        print(self.paint(line, '36'))

    def active(self, unit):
        if unit not in self._active:
            self._active[unit] = subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        return self._active[unit]

    def marked(self, entries):
        units = {'17': 'vpnmanager-limiter.timer', '18': 'vpnmanager-badvpn',
                 '19': 'vpnmanager-online', '20': 'vpnmanager-online',
                 '27': 'vpnmanager-torrent', '28': 'vpnmanager-bot-admin',
                 '29': 'vpnmanager-bot-trial', '34': 'vpnmanager-bot-reseller'}
        config = self.m.load()
        result = []
        for number, label in entries:
            if number in units:
                running = self.active(units[number])
                if number == '20':
                    running = running and config.get('checkuser', False)
                result.append((number, label, running))
            else:
                result.append((number, label))
        return result


    def menu(self):
        page = 1
        while True:
            self.header()
            print(table(self.marked(MAIN_LEFT if page == 1 else MORE_LEFT),
                        self.marked(MAIN_RIGHT if page == 1 else MORE_RIGHT), self.color))
            print(self.paint('\n' + '=' * 47, '36'))
            selected = choice(input('WHAT WOULD YOU LIKE TO DO? : '))
            if selected == '0':
                return
            if selected == '22':
                page = 2
                continue
            if selected == '35':
                page = 1
                continue
            visible = MAIN_LEFT + MAIN_RIGHT if page == 1 else MORE_LEFT + MORE_RIGHT
            if selected not in {choice(key) for key, _ in visible}:
                print('Invalid option.')
                continue
            try:
                self.feature(selected)
            except KeyboardInterrupt:
                print('\nOperation cancelled.')
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                print(f'Error: {error}')
            if self.removed:
                return
            if selected != '10':
                self.pause()

    def username(self):
        names = sorted(self.m.users())
        print('Managed users:')
        for name in names:
            print('  ' + name)
        if not names:
            print('  (none)')
        username = input('Username: ').strip()
        self.m.managed(username)
        return username

    def create(self, trial=False):
        name = input('Username: ').strip()
        secret = input('Password (visible): ')
        self.m.validate_password(secret)
        minutes = int(input('Trial validity in minutes [60]: ') or '60') if trial else None
        if trial and not 1 <= minutes <= 10080:
            raise ValueError('Trial validity must be 1-10080 minutes.')
        days = (minutes // 1440 + 2) if trial else int(input('Validity in days [30]: ') or '30')
        limit = int(input('Simultaneous connection limit [1]: ') or '1')
        if not 1 <= limit <= 1000:
            raise ValueError('Choose a connection limit from 1 to 1000.')
        self.m.create_user(name, days, secret=secret, limit=limit)
        if trial:
            accounts.update(name, expires_at=int(time.time()) + minutes * 60, trial=True)
            print(f'Trial expires in {minutes} minutes. Active sessions will be disconnected by the expiry timer.')
        print('Tip: enable menu 17 to enforce the connection limit.')

    def remove(self, name=None, confirm=True):
        name = name or self.username()
        self.m.managed(name)
        if confirm and input(f'Type {name} to remove this account: ') != name:
            return
        self.m.disconnect(name)
        self.m.run('userdel', name)
        accounts.remove(name)
        print('Removed: ' + name)

    def remove_expired(self):
        names = [name for name in self.m.users() if self.metadata(name)[1]]
        print('Expired users: ' + (', '.join(names) or '(none)'))
        if names and input('Remove these accounts? [y/N]: ').lower() == 'y':
            for name in names:
                self.remove(name, False)

    def report(self, one=None):
        data = self.m.collect()
        counts = collections.Counter(name for values in data['users'].values() for name in values)
        for name in ([one] if one else sorted(self.m.users())):
            record, expired, expiry, locked = self.metadata(name)
            status = 'Expired' if expired else 'Locked' if locked else 'Active'
            connection = f'{counts[name]}/{record.get("limit", 1)}'
            secret = record.get('password', '(reset to display)')
            print(self.paint('-' * 47, '36'))
            for label, value in [('User', name), ('Password', secret), ('Connections', connection), ('Expires', expiry), ('Status', status)]:
                self.field(label, value)

    def monitor(self):
        data = self.m.collect()
        per_protocol = {protocol: collections.Counter(names) for protocol, names in data['users'].items()}
        records = accounts.load()
        for name in sorted(self.m.users()):
            values = [per_protocol.get(protocol, {}).get(name, 0) for protocol in ('ssh', 'dropbear', 'openvpn', 'udp')]
            total = sum(values)
            limit = records.get(name, {}).get('limit', 1)
            print(self.paint('-' * 47, '36'))
            self.field('User', name)
            self.field('Connections', f'{total}/{limit}')
            self.field('SSH / DROP', f'{values[0]} / {values[1]}')
            self.field('OVPN / UDP', f'{values[2]} / {values[3]}')
            print(f'{"Status":<11}: ' + self.state(bool(total)))

    def change_limit(self):
        name = self.username()
        limit = int(input('New simultaneous connection limit: '))
        if not 1 <= limit <= 1000:
            raise ValueError('Choose 1-1000 connections.')
        accounts.update(name, limit=limit)
        print('Limit saved. Enable menu 17 to enforce it.')

    def change_expiry(self):
        name = self.username()
        value = input('Expiry date (YYYY-MM-DD), or number of days from today: ').strip()
        days = int(value) if value.isdigit() else (dt.date.fromisoformat(value) - dt.date.today()).days
        if days <= 0:
            date = dt.date.today() + dt.timedelta(days=days)
            self.m.run('chage', '-E', date.isoformat(), name)
            accounts.update(name, expires_at=None)
            self.m.run('usermod', '-L', name)
            self.m.disconnect(name)
            print('Account expired and disconnected: ' + name)
        else:
            self.m.expiry(name, days)
            self.m.run('usermod', '-U', name)

    def public_endpoint(self, config):
        default = self.m.detect_public_ip() or config.get('endpoint', '')
        suffix = f' [{default}]' if default else ''
        config['endpoint'] = self.m.endpoint(input('Public server IP / domain' + suffix + ': ').strip() or default)
        self.m.save(config)

    def service(self, name):
        self._active = {}
        config = self.m.load()
        active = name in config['enabled']
        options = [('1', 'Install / configure', 'setup'), ('2', 'Turn service OFF', 'stop'),
                   ('3', 'Restart service', 'restart'), ('0', 'Back', None)]
        if name == 'openvpn':
            options[3:3] = [('4', 'Export client file / download link', 'export'),
                            ('5', 'Set public IP / domain', 'endpoint'),
                            ('6', 'Revoke all profile download links', 'revoke')]
        if name == 'online':
            options.insert(3, ('4', 'Change Online App limit', 'app-limit'))
        state = self.state(active and self.active(self.m.SERVICES[name]))
        title = name.upper() + ' [' + state + ']'
        if name == 'tunnel':
            title = 'PROXY / WEBSOCKET [' + state + ']'
            title += ''.join(f'\n{proxy_config.label(item)}: {item["port"]}' for item in proxy_config.listeners(config, configured=True))
            title += '\nNew port adds; same port edits a listener.'
            options.insert(3, ('4', 'Remove one proxy port', 'remove-listener'))
        action = self.m.choose(title, options)
        if action is None:
            return
        if action == 'remove-listener':
            entries = proxy_config.listeners(config, configured=True)
            number = self.m.choose('REMOVE PROXY LISTENER',
                [(str(index), f'{proxy_config.label(entry)}: {entry["port"]}', entry['port'])
                 for index, entry in enumerate(entries, 1)] + [('0', 'Back', None)])
            if number is not None:
                if 'tls' in config['enabled'] and config.get('tls_backend', 'tunnel') == 'tunnel' and config['tunnel_port'] == number:
                    raise ValueError('Change or disable the SSL WebSocket backend before removing this port.')
                config['proxy_listeners'] = [entry for entry in entries if entry['port'] != number]
                self.m.save(config)
                if config['proxy_listeners']:
                    self.m.run('systemctl', 'restart', self.m.SERVICES['tunnel'])
                else:
                    self.m.run('systemctl', 'disable', '--now', self.m.SERVICES['tunnel'])
                    config['enabled'] = [item for item in config['enabled'] if item != 'tunnel']
                    self.m.save(config)
                print(f'Removed proxy listener on TCP {number}.')
            return
        if action == 'app-limit':
            limit = int(input(f'Online App limit [{config.get("online_app_limit", 2500)}]: ') or config.get('online_app_limit', 2500))
            if not 1 <= limit <= 2147483647:
                raise ValueError('Limit must be 1-2147483647.')
            config['online_app_limit'] = limit
            self.m.save(config)
            print('Online App limit saved. The API uses it immediately.')
            return
        if action in ('stop', 'restart'):
            if name == 'squid':
                print('[1/3] ' + ('Stopping' if action == 'stop' else 'Restarting') + ' Squid...', flush=True)
            self.m.run('systemctl', 'disable' if action == 'stop' else 'restart',
                       *(['--now'] if action == 'stop' else []), self.m.SERVICES[name])
            if action == 'stop':
                if name == 'squid':
                    print('[2/3] Saving OFF state...', flush=True)
                config['enabled'] = [item for item in config['enabled'] if item != name]
                self.m.save(config)
            elif name == 'squid':
                print('[2/3] Checking Squid service status...', flush=True)
                self.m.run('systemctl', 'is-active', '--quiet', self.m.SERVICES[name])
            if name == 'squid':
                print('[3/3] Squid ' + ('stopped.' if action == 'stop' else 'restarted.'), flush=True)
            return
        if action == 'endpoint':
            self.public_endpoint(config)
            print('Endpoint saved. Export a new profile if the address changed.')
            return
        if action == 'revoke':
            import profile_links
            print(f'Revoked {profile_links.cleanup(force=True)} download link(s).')
            return
        if action == 'export':
            mode = self.m.choose('EXPORT OPENVPN CLIENT', [('1', 'Save client file', 'file'),
                ('2', 'Create download link', 'link'), ('0', 'Back', None)])
            if mode is None:
                return
            transport = self.m.choose('CLIENT CONNECTION', [('1', 'Direct OpenVPN TCP', 'direct'),
                ('2', 'OpenVPN through HTTP proxy', 'proxy'),
                ('3', 'HTTP Custom / WS payload in app', 'custom-app'), ('0', 'Back', None)])
            if transport is None:
                return
            config['openvpn_client_transport'] = transport
            if transport in ('proxy', 'custom-app'):
                entries = [entry for entry in proxy_config.listeners(config) if 'openvpn' in entry['backends']]
                if len(entries) > 1:
                    number = self.m.choose('OPENVPN PROXY PORT', [(str(index), str(entry['port']), entry['port'])
                        for index, entry in enumerate(entries, 1)] + [('0', 'Back', None)])
                    if number is None:
                        return
                    config['openvpn_client_proxy_port'] = number
            if not config['endpoint']:
                self.public_endpoint(config)
            self.m.save(config)
            server_file = Path('/etc/openvpn/server/vpnmanager.conf')
            shared = config.get('openvpn_key_source', 'shared') == 'shared'
            if not server_file.exists() or shared != ('tls-auth ' in server_file.read_text()):
                self.m.configure('openvpn', config, config['openvpn_port'])
            if mode == 'file':
                self.m.export_client(config, input('Profile output [/root/client.ovpn]: ') or '/root/client.ovpn')
            else:
                import profile_links
                minutes = int(input('Download link validity in minutes [60]: ') or '60')
                if not 1 <= minutes <= 1440:
                    raise ValueError('Choose 1-1440 minutes.')
                # Validate the address before starting the existing web service.
                profile_links.base_url(self.m, config)
                self.m.configure('online', config, config['online_port'])
                url, expires = profile_links.create(self.m, config, minutes)
                print('Download link: ' + url)
                print('Expires: ' + dt.datetime.fromtimestamp(expires).isoformat(sep=' ', timespec='seconds'))
                print(f'Allow TCP {config["online_port"]} in host/provider firewalls for this link.')
                print('Keep this link private. The profile contains a shared TLS authentication key, not the server private key.')
            return
        if name in ('openvpn', 'tunnel', 'tls', 'squid') and not config.get('endpoint'):
            self.public_endpoint(config)
        defaults = {'dropbear': 109, 'sslh': 443, 'badvpn': 7300}
        number = self.m.port(input(f'TCP port [{config.get(name + "_port", defaults.get(name))}]: ') or config.get(name + '_port', defaults.get(name)))
        if name == 'tunnel':
            selected = choice(input('Proxy backends: [1] SSH, [2] OpenVPN, [3] both [3]: ') or '3')
            backends = {'1': ['ssh'], '2': ['openvpn'], '3': ['ssh', 'openvpn']}.get(selected)
            if backends is None:
                raise ValueError('Choose SSH, OpenVPN or both.')
            if len(backends) == 2:
                default = '2' if config.get('proxy_default_backend') == 'openvpn' else '1'
                selected = choice(input(f'Default for GET / without X-Real-Host: [1] SSH, [2] OpenVPN [{default}]: ') or default)
                if selected not in ('1', '2'):
                    raise ValueError('Choose SSH or OpenVPN.')
                config['proxy_default_backend'] = 'ssh' if selected == '1' else 'openvpn'
            else:
                config['proxy_default_backend'] = backends[0]
            self.m.configure_proxy(config, number, backends)
            return
        if name == 'tls':
            backend = self.m.choose('TLS BACKEND', [('1', 'OpenSSH', 'ssh'), ('2', 'OpenVPN', 'openvpn'), ('3', 'HTTP / WebSocket', 'tunnel'), ('0', 'Back', None)])
            if backend is None:
                return
            config['tls_backend'] = backend
        if name == 'squid':
            defaults = ' '.join(config.get('squid_networks', ['127.0.0.1/32']))
            networks = (input(f'Allowed client IPs/CIDRs [{defaults}]: ') or defaults).split()
            if not networks:
                raise ValueError('Enter at least one client IP/CIDR.')
            config['squid_networks'] = networks
        if name in ('dropbear', 'sslh', 'badvpn'):
            getattr(extras, name)(self.m, config, number)
        else:
            self.m.configure(name, config, number)

    def openssh(self):
        config = self.m.load()
        action = self.m.choose('OPENSSH', [('1', 'Configure OpenSSH port', 'setup'),
            ('2', 'Restart managed OpenSSH', 'restart'), ('0', 'Back', None)])
        if action == 'setup':
            number = self.m.port(input('Managed SSH port [2222]: ') or '2222')
            bind = input('Listen address [0.0.0.0]: ') or '0.0.0.0'
            self.m.configure_ssh(config, number, bind)
        elif action == 'restart':
            self.m.run('systemctl', 'restart', 'vpnmanager-sshd')

    def connections(self):
        actions = {'1': self.openssh, '2': lambda: self.service('squid'),
                   '3': lambda: self.service('dropbear'), '4': lambda: self.service('openvpn'),
                   '5': lambda: self.service('tunnel'), '6': lambda: self.service('tls'),
                   '7': lambda: self.service('sslh'), '8': self.xui, '9': self.udp}
        while True:
            self.header('CONNECTION MODE')
            config = self.m.load()
            units = {'1': 'vpnmanager-sshd', '2': self.m.SERVICES['squid'], '3': self.m.SERVICES['dropbear'],
                     '4': self.m.SERVICES['openvpn'], '5': self.m.SERVICES['tunnel'], '6': self.m.SERVICES['tls'],
                     '7': self.m.SERVICES['sslh'], '8': self.m.SERVICES['xui'], '9': self.m.SERVICES['udp']}
            for number, label in CONNECTIONS:
                key = choice(number)
                suffix = ' ' + self.state(self.active(units[key])) if key in units else ''
                print(self.paint(f'[{number}] {label:<25}', '33') + suffix)
            selected = choice(input('WHAT WOULD YOU LIKE TO DO? : '))
            # Return to the caller. Never exit the program or recursively run menu.
            if selected == '0':
                return
            if selected not in actions:
                print('Invalid option.')
                continue
            try:
                actions[selected]()
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                print(f'Error: {error}')
            self.pause()

    def banner(self):
        action = self.m.choose('SSH / OPENVPN LOGIN BANNER', [('1', 'Set banner', 'set'), ('2', 'Remove banner', 'remove'), ('0', 'Back', None)])
        if action is None:
            return
        value = input('Banner text: ') if action == 'set' else ''
        if action == 'set' and input('Format: [1] plain text, [2] HTML [1]: ') == '2':
            import html
            size = int(input('HTML heading size (1-6) [3]: ') or '3')
            color = input('HTML color (name or #RRGGBB) [green]: ') or 'green'
            if not 1 <= size <= 6 or not re.fullmatch(r'[a-zA-Z]+|#[0-9a-fA-F]{6}', color):
                raise ValueError('Invalid heading size or color.')
            value = f'<h{size}><font color="{color}">{html.escape(value)}</font></h{size}>'
        import login_banner
        login_banner.apply(self.m, value)
        print('Banner saved.')

    def traffic(self):
        print(f'{"INTERFACE":<20}{"RECEIVED GiB":>15}{"SENT GiB":>15}')
        for path in sorted(Path('/sys/class/net').iterdir()):
            received = int((path / 'statistics/rx_bytes').read_text()) / 1024 ** 3
            sent = int((path / 'statistics/tx_bytes').read_text()) / 1024 ** 3
            print(f'{path.name:<20}{received:>15.3f}{sent:>15.3f}')
        print('Interface totals since boot, including SSH/VPN traffic.')

    def optimize(self):
        action = self.m.choose('OPTIMIZE SERVER', [('1', 'Refresh / repair / clean package cache', 'packages'),
            ('2', 'Enable TCP BBR when available', 'bbr'), ('3', 'Upgrade distribution packages', 'upgrade'), ('0', 'Back', None)])
        if action == 'packages':
            self.m.run('apt-get', '-o', 'Acquire::Retries=3', 'update')
            self.m.run('apt-get', '-f', 'install', '-y')
            self.m.run('apt-get', 'autoclean')
        elif action == 'upgrade':
            if input('Upgrade installed OS packages now? [y/N]: ').lower() == 'y':
                self.m.run('apt-get', '-o', 'Acquire::Retries=3', 'update')
                self.m.run('apt-get', '-o', 'Acquire::Retries=3', 'upgrade', '-y')
        elif action == 'bbr':
            if not shutil.which('modprobe'):
                extras.package(self.m, 'kmod')
            self.m.run('modprobe', 'tcp_bbr')
            self.m.write('/etc/sysctl.d/91-vpnmanager-bbr.conf', 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n', 0o644)
            self.m.run('sysctl', '-p', '/etc/sysctl.d/91-vpnmanager-bbr.conf')

    def backup(self):
        from private_backup import create, restore_source
        import backup_links
        import secrets
        action = self.m.choose('BACKUP MANAGER', [('1', 'Create private backup', 'create'),
            ('2', 'Restore backup from file / URL', 'restore'), ('3', 'Create encrypted download link', 'link'), ('0', 'Back', None)])
        if action == 'create':
            print('Backup saved: ' + str(create(self.m)))
        elif action == 'link':
            config = self.m.load()
            if not config.get('endpoint'):
                self.public_endpoint(config)
            password = getpass.getpass('Backup password (12+ characters; Enter to generate): ') or secrets.token_urlsafe(24)
            if len(password) < 12:
                raise ValueError('Use at least 12 characters for the backup password.')
            minutes = int(input('Download link validity in minutes [60]: ') or '60')
            if not 1 <= minutes <= 1440:
                raise ValueError('Choose 1-1440 minutes.')
            self.m.configure('online', config, config['online_port'])
            archive = create(self.m)
            url, _ = backup_links.create(self.m, config, archive, password, minutes)
            print('Backup download: ' + url)
            print('Backup password: ' + password)
            print('Save the file and password before the link expires. Restore needs both.')
        elif action == 'restore':
            filename = input('Backup file path or URL: ').strip()
            import progress
            with progress.stage('Detecting current server IP'):
                default = self.m.detect_public_ip() or self.m.load().get('endpoint', '')
            address = input(f'Public IP / DNS after restore [{default}]: ').strip() or default
            # The user selected restore; its authenticated backup is the requested action.
            restore_source(self.m, filename, endpoint=address)

    def hosts(self, remove=False):
        config = self.m.load()
        hosts = config.get('squid_hosts', [])
        print('Squid host list: ' + (', '.join(hosts) or '(empty)'))
        value = input('Host/domain (for example .example.com): ').strip().lower()
        if not re.fullmatch(r'\.?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value):
            raise ValueError('Enter a domain name without a URL scheme, path, spaces or port.')
        self.m.endpoint(value.lstrip('.'))
        if remove:
            if value not in hosts:
                raise ValueError('That host is not in the list.')
            hosts.remove(value)
        elif value not in hosts:
            hosts.append(value)
        config['squid_hosts'] = hosts
        self.m.save(config)
        if 'squid' in config['enabled']:
            self.m.configure('squid', config, config['squid_port'])
        print('Squid host list updated.')

    def auto(self):
        config = self.m.load()
        print('Service startup:')
        for name in config['enabled']:
            result = subprocess.run(['systemctl', 'is-enabled', self.m.SERVICES[name]], capture_output=True, text=True)
            print(f'  {name:<24}' + self.state(result.stdout.strip() in ('enabled', 'enabled-runtime')))
        action = self.m.choose('AUTO EXECUTION', [('1', 'Turn service startup ON', 'enable'),
            ('2', 'Turn service startup OFF', 'disable'), ('0', 'Back', None)])
        if action:
            for name in config['enabled']:
                self.m.run('systemctl', action, self.m.SERVICES[name])
            if Path('/etc/vpnmanager/sshd_config').exists():
                self.m.run('systemctl', action, 'vpnmanager-sshd')

    def update(self):
        checkout = Path('/opt/vpnmanager-source')
        if checkout.exists():
            remote = self.m.capture('git', '-C', str(checkout), 'remote', 'get-url', 'origin')
            if remote != 'https://github.com/sansoe2022/VPN_Manager_Modern.git':
                raise ValueError('The update directory belongs to another repository.')
            self.m.run('git', '-C', str(checkout), 'pull', '--ff-only')
        else:
            extras.package(self.m, 'git')
            self.m.run('git', 'clone', 'https://github.com/sansoe2022/VPN_Manager_Modern.git', str(checkout))
        self.m.run('bash', str(checkout / 'install.sh'))
        print('Updated. Restart services from menu 26.')

    def uninstall(self):
        if input('Type REMOVE to uninstall the manager (accounts and backups stay): ') != 'REMOVE':
            return
        import admission
        pam = Path('/etc/pam.d/sshd')
        if pam.exists():
            rows = [row for row in pam.read_text().splitlines() if row not in (admission.PAM_LINE, admission.PAM_SKIP, '# VPN Manager managed accounts only')]
            self.m.write(pam, '\n'.join(rows) + '\n', 0o644)
        units = list(self.m.SERVICES.values()) + ['vpnmanager-admission', 'vpnmanager-sshd', 'vpnmanager-expire.timer',
            'vpnmanager-limiter.timer', 'vpnmanager-bot-admin', 'vpnmanager-bot-trial', 'vpnmanager-bot-reseller']
        for unit in units:
            result = subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True, text=True)
            if result.returncode and 'does not exist' not in result.stderr and 'not loaded' not in result.stderr and 'No such file' not in result.stderr:
                raise ValueError(result.stderr.strip())
        for path in Path('/etc/systemd/system').glob('vpnmanager-*'):
            if path.is_file() and path.name not in ('vpnmanager-firewall.service', 'vpnmanager-torrent.service'):
                path.unlink()
        self.m.run('systemctl', 'daemon-reload')
        for name in ('vpnmanager', 'vpnmenu', 'menu', 'udpmanager'):
            Path('/usr/local/bin', name).unlink(missing_ok=True)
        shutil.rmtree('/usr/local/lib/vpnmanager')
        self.removed = True
        print('Manager removed. Private config, keys, accounts, backups and firewall rules are retained for review.')

    def feature(self, number):
        aliases = {'criarusuario': '1', 'criarteste': '2', 'remover': '3', 'sshmonitor': '4',
            'mudardata': '5', 'alterarlimite': '6', 'alterarsenha': '7', 'uexpired': '8', 'infousers': '9',
            'conexao': '10', 'speedtest': '11', 'banner': '12', 'trafego': '13', 'otimizar': '14',
            'userbackup': '15', 'swapmemory': '16', 'limiter': '17', 'badvpn': '18', 'onlineapp': '19',
            'initcheck': '20', 'detalhes': '21', 'addhost': '23', 'delhost': '24', 'reiniciarsistema': '25',
            'reiniciarservicos': '26', 'blockt': '27', 'botssh': '28', 'botteste.sh': '29', 'senharoot': '30',
            'autostart': '31', 'attscript': '32', 'delscript': '33', 'botvenda': '34'}
        number = aliases.get(number, choice(number or ''))
        actions = {
            '1': lambda: self.create(), '2': lambda: self.create(True), '3': self.remove,
            '4': self.monitor, '5': self.change_expiry, '6': self.change_limit,
            '7': lambda: self.m.password(self.username()), '8': self.remove_expired,
            '9': self.report, '10': self.connections,
            '11': self.speedtest, '12': self.banner, '13': self.traffic, '14': self.optimize,
            '15': self.backup, '16': lambda: extras.swap(self.m, int(input('Swap size in GiB (0 to disable): '))),
            '17': self.limiter,
            '18': lambda: self.service('badvpn'), '19': lambda: self.service('online'),
            '20': self.checkuser, '21': lambda: self.m.diagnostics(self.m.load()),
            '23': self.hosts, '24': lambda: self.hosts(True), '25': self.reboot,
            '26': lambda: self.m.restart_enabled(self.m.load()),
            '27': lambda: extras.torrent(self.m, input('Enable torrent filtering? [y/N]: ').lower() == 'y'),
            '28': lambda: self.bot('admin'), '29': lambda: self.bot('trial'),
            '30': lambda: self.m.run('passwd', 'root'), '31': self.auto, '32': self.update,
            '33': self.uninstall, '34': lambda: self.bot('reseller')}
        if number not in actions:
            raise ValueError('Unknown menu feature.')
        if number != '10':
            labels = dict((choice(key), label) for key, label in MAIN_LEFT + MAIN_RIGHT + MORE_LEFT + MORE_RIGHT)
            self.page(labels[number])
        return actions[number]()

    def reboot(self):
        if input('Reboot this server now? Type REBOOT: ') == 'REBOOT':
            self.m.run('systemctl', 'reboot')

    def limiter(self):
        on = self.m.load().get('limiter_enabled', False)
        action = self.m.choose('COMBINED CONNECTION LIMITER [' + self.state(on) + ']\nSSH + Dropbear + OpenVPN + UDP share each account limit.\nSet the account limit in menu 06.', [('1', 'Turn limiter ON', True), ('2', 'Turn limiter OFF', False), ('0', 'Back', None)])
        if action is not None:
            extras.limiter(self.m, action)

    def speedtest(self):
        import speed_test
        speed_test.run()

    def xui(self):
        import xui
        action = self.m.choose('X-UI PANEL [' + self.state(self.active(self.m.SERVICES['xui'])) + ']', [('1', 'Install requested x-ui version', 'install'),
            ('2', 'Open x-ui management menu', 'menu'), ('0', 'Back', None)])
        if action == 'install':
            xui.install(self.m)
        elif action == 'menu':
            self.m.run('x-ui')

    def udp_menu(self):
        while True:
            try:
                if self.udp() is None:
                    return
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                print(f'Error: {error}')
            self.pause()

    def udp(self):
        import udp_runtime
        config = self.m.load()
        state = self.state('udp' in config['enabled'] and self.active(self.m.SERVICES['udp']))
        action = self.m.choose('UDP / HYSTERIA 1 [' + state + ']', [('1', 'Install / configure', 'install'),
            ('2', 'Turn UDP OFF', 'disable'), ('3', 'Show client settings', 'client'), ('0', 'Back', None)])
        if action == 'install':
            if not config.get('endpoint'):
                self.public_endpoint(config)
            number = self.m.port(input(f'UDP port [{config.get("udp_port", 36712)}]: ') or config.get('udp_port', 36712))
            config['udp_obfs'] = input(f'Obfuscation [{config.get("udp_obfs") or "svpn"}]: ') or config.get('udp_obfs') or 'svpn'
            udp_runtime.configure(self.m, config, number)
        elif action == 'disable':
            self.m.run('systemctl', 'disable', '--now', self.m.SERVICES['udp'])
            config['enabled'] = [item for item in config['enabled'] if item != 'udp']
            self.m.save(config)
        elif action == 'client':
            print(f'Server: {config.get("endpoint")}; UDP port: {config.get("udp_port", 36712)}')
            print('Hysteria v1; auth: username:password (same account as SSH/OpenVPN).')
            print('Obfuscation: ' + (config.get('udp_obfs') or 'svpn'))
            print('Port hopping: ' + config.get('udp_port_range', '10000-65000'))
            print('SVPN auth_str / [user] must contain username:password, not username alone.')
            print('SNI: ' + config.get('udp_server_name', config.get('endpoint', '')))
            print('CA certificate: /etc/vpnmanager/udp-ca.crt')
        return action

    def checkuser(self):
        config = self.m.load()
        running = config.get('checkuser', False) and self.active(self.m.SERVICES['online'])
        action = self.m.choose('CHECKUSER [' + self.state(running) + ']', [('1', 'Check a managed user locally', 'local'),
            ('2', 'Install / turn CheckUser API ON', 'api'), ('3', 'Turn CheckUser API OFF', 'disable'), ('0', 'Back', None)])
        if action == 'local':
            name = self.username()
            record, _, expiry, _ = self.metadata(name)
            self.field('User', name)
            self.field('Conn limit', record.get('limit', 1))
            self.field('Expires', expiry)
        elif action == 'disable':
            config = self.m.load()
            config['checkuser'] = False
            self.m.save(config)
            print('CheckUser API: ' + self.state(False))
        elif action == 'api':
            config = self.m.load()
            if not config.get('endpoint'):
                self.public_endpoint(config)
            print('Installing / starting CheckUser API...', flush=True)
            self.m.configure('online', config, config['online_port'])
            config['checkuser'] = True
            self.m.save(config)
            print('CheckUser API: ' + self.state(True))
            print(self.api_url(config, '/checkuser'))
            print('HTTP Basic login: managed username/password.')
            print('Response: username, connection_limit, expire_date.')

    def bot(self, role):
        from telegram_bot import configure
        configure(self.m, role)
