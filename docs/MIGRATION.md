# Migration and updates

## Existing VPN_Manager_Modern installation

Pull this repository and rerun `sudo bash install.sh`. Existing users, private
configuration, certificates and keys stay in place. The original-style English
menu replaces the earlier simplified menu. Numbers 01-35 now match the screenshots;
use 26 (More page) to restart services. Existing TLS configs retain their previous
backend unless changed explicitly under 10 → 06.

All menu implementation is source text. `Modulos/` keeps the original entry names
as readable launchers and points into `vpnmanager/classic.py`. Account limit/trial
metadata is stored under `/var/lib/vpnmanager/accounts.json`; old Modern accounts
without metadata default to one connection when the optional limiter is enabled.

## Legacy SSHPlus / original VPN_Manager installation

Use a fresh supported VPS, or first plan a separate manual migration. The original
installation can own `/bin` commands, cron/autostart jobs, overlapping ports, shared
private keys and opaque compiled installers. The installer refuses to overwrite
`/etc/SSHPlus` or `/etc/VPNManager` automatically.

1. Privately save the old account inventory, expiry dates, limits and config.
2. Install this repository on a fresh Ubuntu 20.04+ or Debian 12+ systemd VPS.
3. Configure the same needed services and available ports under 10.
4. Recreate accounts and set their limits/expiry using the original-numbered menu.
5. Install a domain certificate and export new OpenVPN profiles.
6. Test from the target client networks before moving production DNS or retiring the old VPS.

The old ELF menu has been replaced, not decrypted or executed. Telegram/reseller/
trial bots, BadVPN, Dropbear, SSLH and the other screenshot entries now have English
source implementations. Their private runtime state, command formats and backup
format can differ from the opaque original. No V2Ray installation is present.

## Full backup and restore

Menu **15 → 03** creates a complete archive and serves an encrypted copy through
an expiring download link (60 minutes by default, up to 1440). Save both the file
and its separate password before expiry. Press Enter at the password prompt to
generate one. Raw local archives from **15 → 01** remain root-only, mode 600.

Included: installed manager source/assets/native binaries, managed users' password
hashes plus saved report passwords, expiry/limits/trial/bot metadata, OpenVPN PKI,
dedicated SSH host identity, Dropbear host keys, WS listeners, TLS/UDP keys/config,
Squid configuration, manager systemd units, sysctl/firewall scripts, optional BadVPN,
x-ui installation and a consistent SQLite backup of its data. Managed swap is
recreated at its recorded size; its large data file is not copied. Expiring download
tokens and live sessions are not migrated. The administrator's passwd/shadow records,
SSH configuration, unrelated firewall rules and unrelated OS files are preserved.
Custom certificates/data referenced outside these managed directories must be
saved separately or moved into the appropriate managed config directory first.
For optional native panel binaries, prefer the same OS release/runtime as the source.

On a **fresh systemd VPS with the same CPU architecture**, run the public installer
and select **Restore from encrypted backup URL**. It installs distribution packages,
asks for the backup password/current IP, restores source and accounts, regenerates
OS-dependent configs, and starts the configured services. There is no need to
install each VPN protocol manually. A bootstrap/package installation is still
necessary on an empty OS; this is an application backup, not a VPS disk image.

You can also restore using **15 → 02**, a downloaded `.vpnbak` file, or:

```bash
sudo vpnmanager restore 'ENCRYPTED_BACKUP_URL'
```

For an automated fresh bootstrap:

```bash
curl -fsSL https://raw.githubusercontent.com/sansoe2022/VPN_Manager_Modern/main/Plus | sudo bash -s -- --restore-url 'ENCRYPTED_BACKUP_URL' --password-file /root/backup-password --endpoint NEW_IP_OR_DOMAIN
```

Keep the password file root-private. Restore verifies encrypt-then-HMAC integrity
before decrypting or modifying accounts. Archive checks reject paths, links/devices,
duplicate destinations and unmanaged account conflicts. A local before-restore
snapshot is made before replacement. CPU architecture mismatches are rejected.
User port conflicts, provider firewalls, DNS and missing VPS kernel facilities still
need attention. Existing TLS certificates must match the domain used by clients.
UDP keeps its saved SNI/CA identity when the public server IP changes.

Legacy Modern format-1 local archives can still restore their contained accounts
and configuration; they do not contain the newer full source/binary snapshot.
Original opaque `backup.vps` archives are not imported automatically.

Menu 33 stops/removes the manager and its launchers, retaining users, private keys,
configuration and backups. Dedicated OpenVPN/torrent firewall rules remain available
for review rather than flushing the host firewall. Remove only `VPNMANAGER_*` rules
and `/etc/sysctl.d/90-vpnmanager.conf` if the related VPN is no longer needed.
