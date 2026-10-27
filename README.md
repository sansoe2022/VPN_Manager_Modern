# SSHPlus Manager — English Edition

The original two-page SSHPlus menu with readable, unencrypted English source.
Supports **Ubuntu 20.04+** and **Debian 12+**. **V2Ray setup is removed.**

## Install

Run on a systemd VPS with root/sudo access:

```bash
curl -fsSL https://raw.githubusercontent.com/sansoe2022/VPN_Manager_Modern/main/Plus | sudo bash
sudo menu
```

Source:
https://github.com/sansoe2022/VPN_Manager_Modern

## Update an existing Modern installation

```bash
cd VPN_Manager_Modern
git pull --ff-only
sudo bash install.sh
sudo menu
```

Restart configured services with **26** on the More page.

## Menu

- **01–21:** users, monitoring, limits, backup, SSH/VPN/proxy and server tools.
- **10:** original connection menu; **10 → 00** returns to the main menu.
- **22:** More page; **35:** back; **00:** exit.
- SSH, Dropbear, Squid, OpenVPN, HTTP/WebSocket, TLS, SSLH, BadVPN and Telegram bots.

Menu source: [classic.py](vpnmanager/classic.py). Plain launchers: [Modulos](Modulos).
Open the required ports in your host/provider firewalls. OpenVPN requires `/dev/net/tun`.

[Guide](docs/GUIDE.md) · [Migration](docs/MIGRATION.md) · [Validation](docs/VALIDATION.md)
