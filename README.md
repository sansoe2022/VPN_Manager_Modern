# VPN Manager Modern

Readable English source with the original two-page menu.
**Ubuntu 20.04+ · Debian 12+**

## Install / update

```bash
curl -fsSL https://raw.githubusercontent.com/sansoe2022/VPN_Manager_Modern/main/Plus | sudo bash
sudo menu
```

A fresh installation offers **Fresh install** or **Restore from backup URL**.
Restore reinstalls required packages and configured services automatically.
Existing Modern configurations/accounts are retained during updates.

## Main options

- **09:** user/password report. Older unsaved passwords need one reset in **07**.
- **10 → 02:** Squid setup/stop with progress and saved client CIDR defaults.
- **10 → 04 → 04:** OpenVPN profile file/link; choose transport **3** for HTTP Custom WS.
- **10 → 05:** independent SSH/OpenVPN WS ports; adding one preserves the others.
- **10 → 08:** x-ui (sansoe2022 on Ubuntu 20/22 and Debian; alireza0 on Ubuntu 24+).
- **10 → 09:** UDP/Hysteria v1; same username/password as SSH/OpenVPN, no license key.
- **11:** HTTPS download/upload speed test, with download fallback.
- **15 → 03:** encrypted full-backup download link; keep its password separately.
- **15 → 02:** restore from file/URL and start restored services.
- **19 → 04:** shared Online App limit. UDP uses the same online API.
- **20 → 02:** directly install/start CheckUser API (username, connection limit, expiry only).
- **10 → 00:** main menu; **22/35:** More/back; **00:** exit.

The banner separates TCP/UDP ports, shows API links and green ON/red OFF states.
User lists use narrow-screen cards. IP/domain prompts default to the
current detected VPS IP. Menu source and launchers are unencrypted.

UDP supports `svpn` obfuscation and port hopping `10000–65000 → 36712` (or your configured backend port). Use `username:password` for client authentication.
UDP restore updates SNI/certificate names to the chosen current IP/DNS while preserving its CA/keys.
OpenVPN keeps the original shared keys. Full backups include source, keys, managed
accounts, service configs, optional binaries and x-ui data. Restore on the same CPU
architecture; a fresh VPS still needs systemd, network access and required kernel support.
Open provider/host ports yourself; OpenVPN needs `/dev/net/tun`.

[Guide](docs/GUIDE.md) · [Backup / migration](docs/MIGRATION.md) · [Validation](docs/VALIDATION.md)

Menu **12** sends SSH/Dropbear login banners and OpenVPN ECHO messages; client apps control ECHO display. All menus clear the terminal on entry; `udpmanager` opens the integrated UDP menu.
