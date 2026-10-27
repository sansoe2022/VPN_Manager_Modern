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

## Private backups

Menu 15 backs up manager configuration/PKI and only managed-account password hashes,
expiry and metadata. Keep these mode-600 archives private. Restore rejects path
traversal, links/devices and conflicts with unmanaged system accounts, makes its own
pre-restore backup, and does not replace system passwd/shadow files wholesale.

A restored config may require rerunning the installer to regenerate services and
reconfiguring Squid/firewall services before restarting from 26. Original `backup.vps`
archives are not accepted automatically. Inspect and migrate them separately.

Menu 33 stops/removes the manager and its launchers, retaining users, private keys,
configuration and backups. Dedicated OpenVPN/torrent firewall rules remain available
for review rather than flushing the host firewall. Remove only `VPNMANAGER_*` rules
and `/etc/sysctl.d/90-vpnmanager.conf` if the related VPN is no longer needed.
