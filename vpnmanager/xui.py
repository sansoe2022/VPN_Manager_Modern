"""The requested x-ui installers, pinned to inspected source revisions."""
from pathlib import Path
import tempfile
import sqlite3
import downloads

SOURCES = {
    'ubuntu20': ('https://raw.githubusercontent.com/sansoe2022/x-ui/6f1c37f80f300c5337a29f7e4db79351ddc09b09/install.sh',
                 '4274938735650b0723483a6d502981258d14e28523c82e9175165fec67ee650d'),
    'ubuntu24': ('https://raw.githubusercontent.com/alireza0/x-ui/b59efb3f8654c0eafa82386ced0f13aa48a1dc66/install.sh',
                 '309c5d2c5ea9be3851e389933fb1eff53bf08cc6baab5cf4b280fc87726f3568'),
}


def source(release):
    version = int(release.get('VERSION_ID', '0').strip('"').split('.')[0])
    if release.get('ID', '').strip('"') == 'ubuntu' and version == 20:
        return SOURCES['ubuntu20']
    if release.get('ID', '').strip('"') == 'ubuntu' and version >= 24:
        return SOURCES['ubuntu24']
    raise ValueError('The requested x-ui installer mapping supports Ubuntu 20 or Ubuntu 24+. Other manager services remain available.')


def install(m):
    release = dict(row.split('=', 1) for row in Path('/etc/os-release').read_text().splitlines() if '=' in row)
    url, checksum = source(release)
    print('Downloading the requested x-ui installer...', flush=True)
    with tempfile.TemporaryDirectory(prefix='vpnmanager-xui-') as directory:
        script = downloads.fetch(url, Path(directory) / 'install.sh', 2 * 1024 * 1024, checksum)
        # Both upstream installers contain historical wget TLS bypass flags.
        # Retain normal CA verification for their release downloads.
        script.write_text(script.read_text().replace('--no-check-certificate', ''))
        m.run('bash', str(script), cwd=directory)
    m.run('systemctl', 'is-active', '--quiet', 'x-ui')
    config = m.load()
    config['xui_source'] = url
    database = Path('/etc/x-ui/x-ui.db')
    if database.exists():
        try:
            with sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True) as db:
                row = db.execute('SELECT value FROM settings WHERE "key" = ?', ('webPort',)).fetchone()
            if row:
                config['xui_port'] = m.port(row[0])
        except (sqlite3.Error, ValueError):
            pass
    config['enabled'] = sorted(set(config['enabled']) | {'xui'})
    m.save(config)
    print('x-ui installed. Use its displayed panel address and credentials.')
