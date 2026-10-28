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
- **10 → 05:** proxy for SSH, OpenVPN, or both; missing backends are configured.
  Add separate ports for OpenVPN WS and SSH WS; adding a port preserves the others.
- **10 → 04 → 04:** export an OVPN file or download link (default 60 minutes).
  For HTTP Custom with an app payload, choose transport **3**.
- **10 → 00:** return to the main menu.
- **19 → 04:** change the Online App API limit.
- **22:** More page; **35:** back; **00:** exit.
- SSH, Dropbear, Squid, OpenVPN, HTTP/WebSocket, TLS, SSLH, BadVPN and Telegram bots.

Menu source: [classic.py](vpnmanager/classic.py). Plain launchers: [Modulos](Modulos).
The banner labels each listening Connection Mode service and its TCP/UDP port. IP/domain prompts
default to the detected VPS IP (or your saved endpoint). User creation asks username, visible
password, validity, then connection limit (minimum 1 character for username/password).
Menu selections clear the screen before opening each page. OpenVPN uses the original public shared
key bundle on every VPS; existing Modern profiles must be re-exported after switching.

Open the required ports in your host/provider firewalls. OpenVPN requires `/dev/net/tun`.

[Guide](docs/GUIDE.md) · [Migration](docs/MIGRATION.md) · [Validation](docs/VALIDATION.md)
