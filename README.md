# VPN Manager Modern

Readable English VPN/SSH server management for **Ubuntu 20.04+ and Debian 12+**.
Rebuilt from [sansoe2022/VPN_Manager](https://github.com/sansoe2022/VPN_Manager).
The original repository is unchanged. This repository contains a fresh source tree,
without the old binaries, bundled credentials or their Git history.

## Install

Use a fresh VPS with systemd and root access. OpenVPN also requires `/dev/net/tun`.

```bash
sudo apt-get update
sudo apt-get install -y git
# For a private repository, authenticate Git with your GitHub account first.
git clone https://github.com/sansoe2022/VPN_Manager_Modern.git
cd VPN_Manager_Modern
sudo bash install.sh
sudo vpnmanager
```

`menu` and `vpnmenu` are aliases. `Plus` is a readable local installer launcher.
The installer uses distribution packages; it does not add Ubuntu Trusty repositories,
run remote scripts, disable UFW, upgrade the whole OS, or enable root password login.
Optional packages are installed, but listeners are configured explicitly from the menu.
The Squid distribution package may start its default listener during package installation.

## First setup

1. Choose **6** to set your public server IP or DNS hostname.
2. Choose **10 → 1** to create a dedicated SSH backend, normally loopback port 2222.
3. Choose **10 → 5** for HTTP/WebSocket tunneling, normally TCP 80.
4. Choose **10 → 3** for TLS over that tunnel, normally TCP 443.
5. Choose **10 → 4** for OpenVPN TCP, normally TCP 1194.
6. Choose **10 → 2** for Squid, normally TCP 3128. Enter the public client IP/CIDR
   ranges you want to allow. For changing mobile IPs, obtain the relevant ISP ranges
   or use a VPN-side range; a narrow allowlist will reject new source addresses.
7. Choose **10 → 6** for the online status API, normally TCP 81.
8. Create an account with **1 → 1**. Export an OpenVPN profile with **7**.

Only enable the services you need. Explicitly allow their TCP ports in both the host
and hosting provider firewalls. Port conflicts produce errors; no service is moved
silently. Existing administrator SSH settings and login access remain in place.

**Menu 10 → 8 is connection diagnostics. V2Ray/Xray installation is removed.**
All shipped menus, prompts, comments and documentation are English source text.

Ubuntu 20.04 uses its distribution Python 3.8 and OpenVPN 2.4 packages.
The server selects the supported cipher directive and key-generation syntax
automatically. Exported profiles use AES-GCM negotiation compatible with OpenVPN 2.4+.

## Connections

| Service | Default | Client requirements |
| --- | --- | --- |
| SSH backend | 127.0.0.1:2222 | Managed account; use forwarding / no-session mode (`ssh -N`) through a tunnel |
| HTTP/raw upgrade | TCP 80, `/ssh` or `/` | HTTP upgrade client followed by a raw TCP stream |
| WebSocket | TCP 80, `/ssh` | RFC 6455 binary frames; standard Upgrade headers and version 13 |
| OpenVPN tunnel | TCP 80, `/openvpn` | HTTP/raw or framed WebSocket tunnel to OpenVPN TCP |
| TLS | TCP 443 | TLS 1.2+ wrapping the HTTP/WebSocket tunnel; use `/ssh` or `/openvpn` after TLS |
| OpenVPN direct | TCP 1194 | OpenVPN 2.4+ client and exported profile; managed username/password |
| Squid | TCP 3128 | Allowed source IP; CONNECT destination `127.0.0.1:2222` or configured local VPN port |
| Online API | TCP 81 | `/server/online_app`, `/server/online`, `/online`, `/health` |

The TLS setup generates a unique self-signed certificate. For normal certificate
verification, replace `/etc/vpnmanager/tls.pem` with a PEM containing your domain's
certificate chain and private key (mode 600), then restart `vpnmanager-tls`.
Use a domain whose DNS resolves to this server. Do not disable certificate verification.
This TLS listener carries HTTP tunneling, not a direct SSH protocol greeting.

Squid is limited to configured client source ranges and fixed loopback VPN backends.
It is not a general Internet browsing proxy. A `403` usually means the source IP,
CONNECT destination or destination port is outside that policy.

OpenVPN uses PAM account authentication and a server-specific CA/TLS key. Client
profiles contain the CA certificate and shared tls-crypt key, never the server private
key. Keep profiles private. Old profiles and shared keys from the original project
must be replaced. VPN egress is IPv4; IPv6 client traffic is not routed by this setup.
If a client needs full traffic containment, disable its IPv6 or configure a separate
IPv6 VPN policy before using this IPv4 profile.

## Online count and ISP diagnosis

```bash
sudo vpnmanager online
sudo vpnmanager diagnostics
curl http://YOUR_SERVER:81/server/online_app
# {"onlines": "3", "limite": "2500"}
```

`limite` retains the old app's display field; it is not an enforced connection limit.
The API returns session counts only; detailed user names are shown by the local CLI.
It counts post-authentication SSH sessions and OpenVPN `CLIENT_LIST` records,
excluding listeners, privilege monitors, routes and stale OpenVPN status files.
One person using both protocols counts twice. Counts refresh on request; OpenVPN
writes status every 10 seconds. Administrator accounts are excluded. Other standalone SSH/OpenVPN services using
the same managed accounts may also be counted when their process/status format matches. The API has no authentication and should
be firewalled to its consumers or placed behind an authenticated HTTPS reverse proxy.

The count does not depend on ISP identity. Actual reachability does: ISPs can block
server addresses, DNS answers, ports or protocols. No server script can guarantee
access through every ISP. For a failing client, record ISP, app/protocol, exact error,
server logs and the result of testing the same profile on a working network.

Check A/AAAA DNS records, certificate verification, provider firewall, host firewall,
source CIDR policy and TCP listener first. The default listeners are IPv4; do not
publish an AAAA record pointing at an unconfigured IPv6 listener. For MTU problems
(connected but large transfers stall), test `tun-mtu 1400` in the client profile.
Changing payload text cannot fix a blocked server IP. The program does not spoof
network access or promise free ISP traffic.

## Operations

Config: `/etc/vpnmanager/config.json`. Restart affected services after manual edits.
The menu supports create/trial accounts, passwords, expiry renewal, locking,
unlocking, deletion, online sessions, logs, service restart and private config backup.
Expiry is enforced by PAM for new sessions; a systemd timer disconnects already
connected expired/locked accounts every minute. User accounts have no interactive shell.
Backups omit OS account passwords; see [migration](docs/MIGRATION.md).

```bash
sudo systemctl status vpnmanager-tunnel vpnmanager-online vpnmanager-tls
sudo journalctl -u vpnmanager-tunnel -n 80 --no-pager
sudo journalctl -u openvpn-server@vpnmanager -n 80 --no-pager
```

For OpenVPN, dedicated `VPNMANAGER_NAT` and `VPNMANAGER_FWD` iptables chains provide
IPv4 forwarding/NAT and are restored by `vpnmanager-firewall.service` at boot.
Do not choose a VPS whose existing network overlaps `10.80.0.0/24`.
Reloading UFW or another firewall manager may remove these rules; restart
`vpnmanager-firewall` afterwards and verify your firewall's forwarding policy.

Update by reviewing/pulling this repository, then rerunning `sudo bash install.sh`.
Existing modern configuration/PKI and user accounts are retained. Restart enabled
services from menu **4** after updating. Back up first; in-place legacy upgrades
are deliberately refused. Future Ubuntu/Debian releases require the same checks
before they can be described as tested.

## Validation

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh Plus
# Disposable container only:
docker build --build-arg DISTRO=debian:13 -f tests/Dockerfile -t vpnmanager-test .
docker run --rm vpnmanager-test
```

CI covers Ubuntu 20.04/22.04/24.04 and Debian 12/13. Container tests exercise real SSH/PAM
login and forwarding, online counting, expired-session disconnection, real Squid
CONNECT and deny rules, TLS daemon startup, OpenVPN PKI/profile generation and tunnel
binary data transfer. Container tests substitute systemctl/sysctl; they do not prove
systemd reboot behavior, a routed OpenVPN connection or ISP reachability. Complete
[the VPS acceptance checklist](docs/ACCEPTANCE.md) before production use.
