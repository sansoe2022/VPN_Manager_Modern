# Validation record

Date: 2026-10-28. Architecture: amd64. Disposable distro containers.

The original-numbered English menu is covered by 50 unit checks, including the
specific **10 → 00 → main menu**, **22 → More → 35 → main menu** paths. The removed
standalone V2Ray installer remains removed. Main-page/More-page numbers and
connection entries 01–07 are retained; 08/09 now expose requested x-ui/UDP setup.

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
- OpenVPN shared-key verification and parser acceptance of server/client configs.
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


2026-10-28 changes: original shared bundle identity across server directories,
profile GET/HEAD download headers, expiry/revocation, token log redaction, private-key
exclusion, automatic SSH/OpenVPN proxy provisioning, legacy local-target routing,
listening-port banner parsing and visible password prompt order, single-character credentials and fresh feature pages are covered. The
distro integration also checks stable shared key hashes across repeated setup and
backup restore, plus actual client-profile HTTP download and proxy-profile parsing.

The follow-up proxy checks run `tests/openvpn_live.py` with NET_ADMIN in disposable
containers: real server/client TLS, PAM username/password authentication and TUN
initialization over direct TCP, original raw HTTP payload, HTTP CONNECT, framed
RFC 6455 WebSocket, the exported native HTTP-proxy profile, a two-stage
`CONNECT /` + `CF-RAY /` app payload, and an outer verified SSL connection on 443.
The setup configures OpenVPN WS 8880 followed by SSH WS 2086 through the actual
configuration functions, then starts the persisted multi-listener CLI worker. A real
SSH password session through 2086 stays connected during all seven OpenVPN modes.
This tests actual OpenVPN sessions rather than only parser output. All modes passed on Ubuntu
20.04/22.04/24.04/26.04 and Debian 12/13. It does not test provider firewalls,
public IPv4 egress/DNS, HTTP Custom's proprietary app behavior, or ISP filtering.
Unit checks also cover IP prompt defaults, original 0.0.0.0/X-Real-Host routing on
custom paths and filtering unrelated listening ports out of the menu banner.
Further regression checks cover preserving independent proxy ports during edits,
selecting the OpenVPN port after editing SSH, labeling the four requested services,
and consuming fragmented/pipelined extra HTTP headers without changing binary data.


## Shared UDP and full migration checks

`tests/udp_live.py` runs the pinned Hysteria v1.3.5 binary with a real client,
verified TLS, native TCP/UDP relays, one-character shared Unix credentials, password
changes, expiry rejection and merged online/disconnect counts. It passed on all
six distributions above. There is no separate UDP users database or Redis fixture.

`tests/migration_smoke.py` exports a full encrypted backup from Ubuntu 20, restores
it by HTTP URL into a fresh Debian 13 container, checks private-key hashes, account
password/expiry/limit data, source/binary files, SQLite x-ui fixture data, launchers
and service reconstruction. It then runs real SSH/OpenVPN/WS/SSL/UDP clients on
the restored state. Administrator shadow data remains unchanged. Container systemd
commands and package installation are simulated; their actual daemons/libraries
are exercised. Boot activation and a full fresh VPS package/network test remain
in the acceptance checklist. x-ui tests cover OS selection, script checksum/syntax
and data migration fixtures, not a live public panel installation.

Crypto tests cover round-trip, wrong passwords/tampering before restore, link
expiry/redaction and strict archive paths. The speed-test path has local HTTP
transfer tests; its primary public HTTPS download and upload endpoints were also
verified with a small transfer through the execution environment's network path.
That measurement does not describe the user's VPS bandwidth.
The installer prompt check uses a real pseudo-terminal for fresh/URL-restore
selection and verifies noninteractive restore argument forwarding on Ubuntu 20.
