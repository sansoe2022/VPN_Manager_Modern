# VPN Manager Modern — SSHPlus English menu

The original **two-page SSHPlus menu and option numbers** are restored, as shown in
the reference screenshots. The menu and its features are readable English source;
there is no encrypted/compiled menu payload. V2Ray/Xray setup is removed.

Source: [sansoe2022/VPN_Manager](https://github.com/sansoe2022/VPN_Manager).
Changes are published here, in `VPN_Manager_Modern`; the original repository is unchanged.

Supported baseline: **Ubuntu 20.04+ and Debian 12+**, with systemd and root access.
Compatibility checks cover Ubuntu 20.04/22.04/24.04/26.04 and Debian 12/13.
Future releases still require acceptance testing; no script can guarantee an
unreleased OS or access through every ISP.

## Install or update

Public one-line installer (after the repository is public):

```bash
curl -fsSL https://raw.githubusercontent.com/sansoe2022/VPN_Manager_Modern/main/Plus | sudo bash
```

The readable bootstrap clones this repository over HTTPS, runs its installer and
removes only its own temporary checkout. You can also clone and inspect it first:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/sansoe2022/VPN_Manager_Modern.git
cd VPN_Manager_Modern
sudo bash install.sh
sudo menu
```

For an existing **Modern** install:

```bash
cd VPN_Manager_Modern
git pull --ff-only
sudo bash install.sh
sudo menu
```

Use **26** on the More page to restart configured services after updating. Existing
Modern accounts, configuration and keys are retained. See [migration](MIGRATION.md)
for the old SSHPlus installation; its opaque jobs are not executed or overwritten.

`menu`, `vpnmenu` and `vpnmanager` open the same original-style menu.
`Plus` launches the local installer. `Modulos/menu` and the original module entry
names are plain shell launchers; their complete readable implementation is in
[vpnmanager/classic.py](../vpnmanager/classic.py), with OS operations in
[vpnmanager/manager.py](../vpnmanager/manager.py). No menu is compiled during installation.

## Original menu layout

```text
[01] CREATE USER         [11] SPEED TEST
[02] CREATE TRIAL USER   [12] BANNER
[03] REMOVE USER         [13] TRAFFIC
[04] ONLINE MONITOR      [14] OPTIMIZE
[05] CHANGE EXPIRY       [15] BACKUP
[06] CHANGE LIMIT        [16] VIRTUAL MEMORY
[07] CHANGE PASSWORD     [17] LIMITER
[08] REMOVE EXPIRED      [18] BADVPN PRO
[09] USER REPORT         [19] ONLINE APP
[10] CONNECTION MODE     [20] CHECKUSER
[00] EXIT                [21] VPS INFO
                         [22] MORE >>>

[23] ADD HOST            [30] ROOT PASSWORD
[24] REMOVE HOST         [31] AUTO EXECUTION
[25] REBOOT SYSTEM       [32] UPDATE SCRIPT
[26] RESTART SERVICES    [33] REMOVE SCRIPT
[27] BLOCK TORRENT       [34] RESELLER BOT
[28] TELEGRAM BOT        [35] BACK <<<
[29] TRIAL BOT           [00] EXIT <<<
```

The terminal menu has the red title, system/RAM/CPU information, online/expired/total
counts, colored separators and two columns, sized for a 47-column terminal.
`*` marks a running optional service and `o` marks an inactive one.
**22** opens More; **35** returns to the first page; **00** exits the main menu.

Connection mode (**10**) keeps the original order:

```text
[01] OPENSSH
[02] SQUID PROXY
[03] DROPBEAR
[04] OPENVPN
[05] PROXY / WEBSOCKET
[06] SSL TUNNEL
[07] SSLH MULTIPLEX
[08] X-UI PANEL
[09] UDP / HYSTERIA
[00] BACK TO MAIN MENU
```

**10 → 00 returns directly to the main menu. It never exits the program.**
The old standalone V2Ray installer remains removed. At the owner's request, **08** now installs x-ui and **09** configures UDP; entries 01–07 retain their numbers.

## First configuration

1. **10 → 01:** configure a managed OpenSSH listener, normally TCP 2222. Choose
   `0.0.0.0` for direct IPv4 access or `127.0.0.1` for tunnel-only access. The
   administrator's existing SSH listener is preserved; occupied ports are rejected.
2. **10 → 03:** optionally enable Dropbear, normally TCP 109.
3. **10 → 05:** configure the HTTP/WebSocket proxy, normally TCP 80.
4. **10 → 06:** configure TLS, normally TCP 443; select SSH, OpenVPN or the
   HTTP/WebSocket proxy as its backend. Select the proxy for WSS clients.
5. **10 → 04:** configure OpenVPN TCP, normally TCP 1194; use its Export option
   to set the public endpoint and write a private client profile.
6. **10 → 02:** configure Squid and the allowed public client IP/CIDR ranges.
7. **01/02:** create regular/trial accounts; **06** sets limits, and **17** enables
   the background limiter. **19** configures the online API.

Allow the selected TCP ports in the host and hosting provider firewalls. Services
are enabled explicitly; the distribution Squid package can start its default
listener when first installed. The installer never disables UFW or enables root
password SSH login. OpenVPN additionally requires `/dev/net/tun`.

## Feature behavior

- **Accounts:** create/remove, minute-based trials, expiry renewal, passwords,
  online monitor/report, expired-account cleanup, and per-user simultaneous limits.
  PAM rejects expired accounts; the expiry timer also locks and disconnects expired
  or locked sessions every minute. The optional limiter checks every 15 seconds and
  disconnects an account exceeding its limit across SSH, Dropbear, OpenVPN and UDP.
  Forwarding accounts have no interactive shell; use SSH forwarding/no-session mode.
- **Banner/traffic/optimization:** text or HTML SSH banner, network byte totals,
  package repair/cache cleanup, optional package upgrades and BBR when the host kernel supports it.
- **Backup:** complete manager/application migration with source, keys, credentials,
  optional service binaries and x-ui data. Menu 15 → 03 publishes an encrypted expiring
  download; 15 → 02 restores from file/URL and activates services. Raw local archives
  remain root-only. See [full migration](MIGRATION.md).
- **Virtual memory:** creates/removes only `/var/lib/vpnmanager/swapfile`, with a
  corresponding fstab entry. Other swap devices/files are preserved.
- **BadVPN Pro:** builds BadVPN UDPGW from the pinned upstream 1.999.130 source
  revision, rather than executing the old bundled ELF. Requires Git, CMake and a C
  compiler, installed when selected. The default listener is loopback TCP 7300.
- **Squid hosts:** 23/24 add/remove destination domains. Client source CIDRs still
  apply. Local VPN backend ports are allowed; added domains use ports 80/443.
  A changing mobile public IP may require an appropriate ISP source range.
- **Torrent filtering:** dedicated port/signature rules, without flushing the
  administrator firewall. Encrypted BitTorrent cannot be reliably identified by
  these signatures. Auto execution, service restart, root password change, update,
  reboot and removal are available under their original numbers.
- **Telegram/trial/reseller bots:** readable English implementations in
  `telegram_bot.py`. Configure a separate BotFather token and numeric owner ID for
  each role. Only private chats are accepted. Trial bots allow one trial per user
  per 24 hours; reseller quotas and account ownership are enforced. Tokens stay in
  root-only files. Use `/help` in the bot for commands. See [bot commands](BOTS.md).

These features reproduce the original menu's functions in source form; they do not
execute or decrypt the original ELF menu/bot installers or download their opaque
payloads. Advanced third-party bot extensions and old private backup/API wire formats
are not claimed to be identical. The supported behavior is described above and in code.

## Proxy, TLS and online APIs

The proxy accepts raw HTTP upgrade/CONNECT streams and framed RFC 6455 WebSockets.
Use `/ssh` for SSH and `/openvpn` for OpenVPN. In both-backend mode, the setup prompt
selects which backend plain `GET /` uses. Backends are fixed local
services; client destination headers cannot select arbitrary internal services.
TLS wraps the backend selected in menu 10 → 06. A unique self-signed certificate
is generated initially. Replace `/etc/vpnmanager/tls.pem` with your domain's verified
certificate chain and key, mode 600, then restart `vpnmanager-tls` for normal public trust.

OpenVPN automatically handles Ubuntu 20.04's 2.4 key-generation/cipher options and
newer versions. Profiles use managed username/password authentication and contain
only the CA and shared tls-auth key, never the server private key. Keep profiles private.
VPN routing/NAT is IPv4; configure client IPv6 containment separately if needed.

Online API (normally TCP 81):

- `/server/online_app` → `{"onlines":"3","limite":"2500"}`
- `/server/online` and `/online` → plain session count
- `/health` → health response
- `/checkuser` → enabled through **20**, HTTP Basic authentication with a managed
  account, returning only that account's status/expiry/limit/count. Put HTTPS in front
  of it before sending passwords over an untrusted network.

Counts include authenticated managed SSH, Dropbear and OpenVPN sessions, excluding
administrators/listeners and stale OpenVPN status files. One person using two protocols
counts twice. Dropbear's supervised authentication events and process start identity
avoid counting unauthenticated/root-owned listeners or reused process IDs. `limite`
retains the legacy display value; per-account enforcement is controlled by menu 17.

## Compatibility and verification

```bash
python3 -m unittest discover -s tests -v
for script in install.sh Plus menu Modulos/*; do bash -n "$script"; done
docker build --build-arg DISTRO=ubuntu:20.04 -f tests/Dockerfile -t vpnmanager-test .
docker run --rm vpnmanager-test
```

See [validation](VALIDATION.md) and the [VPS acceptance checklist](ACCEPTANCE.md).
Container tests exercise real SSH/Dropbear login and forwarding, Squid CONNECT,
TLS/SSLH, online counts, expiry, account backup/restore and OpenVPN config generation.
They substitute systemctl/sysctl; production reboot, routed VPN egress, swap/kernel
firewall capabilities and live Telegram/ISP access still need a VPS/client test.

For a failing ISP, compare the same client/profile on another network and check DNS,
A/AAAA records, certificate verification, provider/host firewalls, allowed Squid source
ranges and listener ports. The default public listeners are IPv4; do not advertise an
AAAA record without an IPv6 listener. No menu/payload can guarantee every ISP permits
an IP address or protocol. Use **21** for diagnostics and `journalctl` for service logs.


## OpenVPN keys, downloads and proxy mode

The default `openvpn_key_source` is `shared`: the exact original key bundle is used
on every VPS and is not regenerated. It uses tls-auth, SHA256 and AES-GCM/CBC
compatibility. Certificates expire in May 2036. This private key is intentionally
public/shared, as requested, so it does not provide server-unique secrecy. To retain
server-unique mode instead, explicitly set `openvpn_key_source` to `unique` before
configuring OpenVPN. Switching key/auth modes requires re-exporting client profiles.

10 → 04 → 04 offers local file or download link and direct TCP, HTTP proxy, or
HTTP Custom / app-payload mode. Choose transport **3** when the app injects the
WS/HTTP payload: it exports the public proxy port without an `http-proxy` directive.
Use the proxy port from **10 → 05**, not the Online App port (normally 81).
For a raw HTTP Custom payload:

```text
GET /openvpn HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```

The `[crlf]` markers denote CRLF line breaks; use your app's equivalent if different.
Do not add an extra OpenVPN `http-proxy` handshake when the app already supplies it.
Transport **2** supplies standard HTTP CONNECT itself and needs no injected payload.
Links use the existing web service (normally TCP 81), random tokens and a 1-1440
minute expiry (default 60). They serve only client profiles, with no server private
key or stored user passwords. Open the download port in the host/provider firewall.
10 → 04 → 06 revokes links. An HTTPS reverse proxy can be used by setting
`download_base_url` to its public URL in the private config.

10 → 05 selects SSH, OpenVPN or both (default both). Missing SSH is created on
loopback TCP 2222 without modifying administrator SSH; OpenVPN is configured as TCP.
Each setup adds or edits **one port** without replacing other proxy listeners.
For separate services, configure port **8880 → OpenVPN**, then **2086 → SSH**.
Both listeners run together, and `.ovpn` proxy/app exports select an OpenVPN-capable
port rather than whichever listener was edited last. With multiple OpenVPN-capable
listeners, the export menu lets you choose. Option 4 removes one proxy port;
Disable service stops all proxy listeners. Existing single-port configurations are
read automatically; a port overwritten by an older release must be added again.
For **OpenVPN SSL 443**, set 10 → 06's backend to **OpenVPN**. In a custom app,
enable its outer SSL/TLS wrapper and trust a valid server certificate; use a direct
OVPN profile with the app's SSL port override, without a WS/HTTP payload.
Use `/ssh`, `/openvpn`, or a local HTTP CONNECT target. Legacy `X-Real-Host` headers
are limited to the enabled local SSH/OpenVPN ports. The exported HTTP proxy profile
uses standard CONNECT to the OpenVPN backend, so a raw WebSocket adapter is unnecessary.
Original `X-Real-Host: 0.0.0.0:1194` and `127.0.0.1:1194` payloads are accepted on
arbitrary HTTP paths, including absolute URLs; destinations still map only to the
configured local backend. Carrier paths without a target use the selected default;
explicit `/ssh` and `/openvpn` require that backend to be enabled.
Real framed RFC 6455 WebSockets remain supported.

Legacy app payloads with `CONNECT /` followed by a second `CF-RAY / HTTP/1.1`
header are handled as a single raw tunnel. The second HTTP preface is consumed,
including when split across TCP packets; it is not forwarded into SSH/OpenVPN data.
This behavior is separate from framed RFC 6455 WebSocket mode.

The app's **proxy hostname must resolve to this VPS** for a direct connection.
DNS-only mode still uses the IP stored in its A/AAAA record: check that the actual
proxy hostname points to the VPS, not another origin or a Cloudflare edge address.
An HTTP 521 response indicates an upstream origin failure, not a successful tunnel;
replacing the response text with 200 in the app cannot repair the connection.
Test with the VPS IP and the appropriate proxy port before adding any intermediate proxy.

IP/domain prompts offer the saved endpoint, otherwise the detected public VPS IP;
press Enter to accept it. If external detection is unavailable, enter it manually.
The menu banner names each actual Connection Mode listener, for example:

```text
TCP Ports:
  OpenVPN: 1194
  OpenVPN WebSocket: 8880
  SSH WebSocket: 2086
  OpenVPN SSL: 443
UDP Ports: (none)
```

It excludes
unrelated/ephemeral ports, the Online App port, and private SSH helper listeners.
OpenVPN/proxy setup checks that its TCP listener opened before reporting success;
startup failures include recent service journal messages. Updates restart running
proxy/online workers to load the new source.

The original shared keys stay the same on a new VPS. Accounts/configuration still
need migration via menu 15. Update the public endpoint under 10 → 04 → 05 when its
IP/domain changes; old profiles with an old IP must be edited or exported again.

Online App menu 19 → 04 updates `limite` immediately without a restart. It is the
app's advertised capacity, separate from the per-user limiter in 06/17.

## Branding, passwords and Squid

The title is `VPN Manager Modern | make with Ai by sansoe`.
Menu 09 displays the username and saved password alongside expiry/status/online
counts. Passwords set from now on are retained in root-only account metadata;
older hashed passwords cannot be recovered and show `(reset to display)` until reset
using 07. The public online/CheckUser API never exposes these report passwords.
Squid setup/stop/restart prints real operation stages, and allowed client CIDRs
have a displayed saved default. IP/domain prompts offer the current detected VPS
IP first and the saved endpoint if detection is unavailable.

## UDP and x-ui

**10 → 09** integrates Hysteria **v1.3.5**, matching the supplied UDP project.
Its native binary comes from the pinned upstream release with a SHA-256 check;
there is no install-key server/loader, second users database, Redis, or separate
online web server. Create a user once in 01/02 (or a bot): SSH, OpenVPN and UDP
use the same account. Hysteria v1 client auth is `username:password`; choose the
configured UDP port (default 36712), obfuscation and saved SNI. Trust the server's
`/etc/vpnmanager/udp-ca.crt` or install a certificate valid for your domain.

The supervised daemon records successful authenticated QUIC connections and
removes them on the server's disconnect event. Abruptly closed clients can remain
counted until the negotiated QUIC idle timeout (commonly 20 seconds, up to 60).
Its total is merged into menu 04, the banner, CheckUser and `/server/online[_app]`.
Old `/udpserver/online[_app]` paths alias that same aggregate on the same web port.
Passwords, locks, deletions and expiry use the shared Unix account data. With menu
17 enabled, UDP admissions and combined limits use the same per-account limit.
Hysteria v1 lacks a per-client disconnect control API: revoking an active UDP
session restarts the UDP daemon, so other valid UDP clients may briefly reconnect.

**10 → 08** installs x-ui using the requested Ubuntu mapping: the sansoe2022 fork
on 20 and alireza0 on 24+. Ubuntu 22/Debian have no requested x-ui mapping and this
optional installer reports that explicitly; all other manager features remain
available. Installer source is pinned/checksummed; upstream release downloads keep
TLS certificate verification enabled. x-ui retains its own panel/inbound settings,
and its installation/database are included in full backups. The old separate
V2Ray menu installer has not been reintroduced.

Menu **11** uses a single-connection HTTPS bandwidth test (roughly 33 MB), showing
HTTPS latency plus download/upload Mbps. If the primary server is unavailable,
it attempts an OVH download-only fallback and labels upload as unavailable.
