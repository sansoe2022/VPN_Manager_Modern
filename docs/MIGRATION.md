# Migration from VPN_Manager / SSHPlus

Use a fresh supported VPS. The legacy installer has overlapping `/bin` commands,
cron/autostart jobs, copied private keys, compiled modules and third-party installers.
This rewrite does not execute, import or uninstall those components automatically.
Keep the old VPS available until replacement connections have been verified.

1. Privately back up your original configuration and account inventory.
2. Install this repository on a fresh Ubuntu 20.04/22.04/24.04 or Debian 12/13 VPS.
3. Configure only the services and ports your clients require.
4. Recreate accounts using new passwords and the desired expiry dates.
5. Install your domain certificate, verify DNS/firewalls, and export new profiles.
6. Test clients on each target ISP before changing production DNS or retiring the old VPS.

The duplicate `Sistema`, `Install`, `Slowdns` and legacy `Modulos` trees are not shipped.
They contained obsolete bundled binaries/packages, credentials, duplicate scripts,
Portuguese menus, external installers and unused assets. V2Ray/Xray is removed.
Legacy Telegram sales bots, SlowDNS, BadVPN, Trojan, Dropbear, arbitrary shell tuning,
root password changes, swap tools and automatic self-updaters are not carried forward.
These features were not ported or tested; no menu entry pretends to run them.
Core account management, online monitoring, SSH/HTTP/WebSocket/TLS, OpenVPN and Squid
have been replaced by the readable implementation in `vpnmanager/`.

Backups from menu 5 are private configuration/PKI archives, not whole-system backups.
They contain sensitive keys. Keep mode 600 and copy them over a trusted channel.
Restore configuration manually on a compatible server after inspecting the archive;
reinstall packages/units, recreate accounts, and restart services. The backup does
not contain passwords, administrator SSH config, Squid's previous config or firewall
state. Existing Squid config is separately preserved under
`/var/lib/vpnmanager/backups/squid.conf.before-vpnmanager` on first configuration.

To disable the modern deployment, disable its configured units and the expiry timer.
Do not remove the administrator SSH service or flush the host firewall. Review and
remove only the `VPNMANAGER_*` chains/jumps and `/etc/sysctl.d/90-vpnmanager.conf`
when OpenVPN is no longer needed. Retain PKI until all replacement profiles are issued.
