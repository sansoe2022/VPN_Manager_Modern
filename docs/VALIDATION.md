# Validation record

Date: 2026-10-27. Architecture: amd64. Disposable distro containers.

The original-numbered English menu is covered by 22 unit checks, including the
specific **10 → 00 → main menu**, **22 → More → 35 → main menu** paths. The removed
V2Ray slot is rejected without closing the program. All main-page/More-page numbers
are retained, and every connection entry except 08 keeps its original number.

Compatibility matrix: Ubuntu 20.04/22.04/24.04/26.04 and Debian 12/13.
The integration script checks real distribution daemons/libraries:

- OpenSSH and Dropbear password login and TCP forwarding.
- Authenticated online counts, including root-owned Dropbear forwarding sessions.
- Dropbear process start identity, preventing stale/PID-reuse counts.
- Expiry disconnection across SSH and Dropbear.
- libcrypt password verification, including Python versions without the crypt/spwd modules.
- Squid CONNECT to an allowed backend and denial of an unallowed destination.
- TLS listener startup and a verified TLS-to-SSH connection.
- SSLH startup and routing an actual SSH handshake.
- OpenVPN CA/server-key generation and parser acceptance of server/client configs.
- Managed-account backup/restore with password hashes and metadata; the administrator's
  shadow record remains unchanged.
- Generated initial systemd units pass `systemd-analyze verify`.

The pinned upstream BadVPN 1.999.130 revision
`752c6b492bc6866e8af8313a6e348d5e0370fe1f` is separately compiled and its binary started.
No opaque binary from the original repository is shipped or executed.

Offline checks cover metadata persistence, trial-expiry boundaries, combined-protocol
limits, backup path/link rejection, bot owner/reseller authorization/quota rules,
WebSocket framing, fragmented HTTP headers and legacy API field names. They do not
contact Telegram or send real messages.

Systemctl/sysctl are substituted in daemon integration checks: containers do not have
systemd PID 1 or a routed TUN device. Full installation/reboot, routed OpenVPN egress,
real Telegram tokens/chats, speed-test providers, swap/kernel firewall capabilities,
ARM64 and individual ISP reachability require a real VPS/client acceptance run.
See [ACCEPTANCE.md](ACCEPTANCE.md). Future OS releases require their own check run.
