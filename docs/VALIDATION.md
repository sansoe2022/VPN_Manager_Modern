# Validation record

Date: 2026-10-27. Architecture: amd64. Disposable Docker containers.

| Distribution | Unit checks | Integration checks |
| --- | --- | --- |
| Ubuntu 22.04 | 8 passed | Passed |
| Ubuntu 24.04 | 8 passed | Passed |
| Debian 12 | 8 passed | Passed |
| Debian 13 | 8 passed | Passed |

Integration checks use real distribution OpenSSH/PAM, Squid, stunnel, OpenSSL,
EasyRSA and OpenVPN packages. They verify SSH password authentication and TCP
forwarding, live online counts, termination of expired accounts, Squid's allowed
CONNECT and denied destination rules, TLS listener startup, unique CA/server key
creation, and OpenVPN profile generation without a server private key. Generated
systemd units pass `systemd-analyze verify`.

Unit checks exercise OpenSSH's old and new process formats, administrator-session
exclusion, OpenVPN CSV/TSV parsing, legacy API field names, CIDR/input validation,
fragmented HTTP headers with pipelined binary data, framed WebSocket binary transfer,
and rejected unknown tunnel routes.

Systemctl/sysctl calls are substituted in container integration checks. There is
no systemd PID 1 or routed TUN device. These results do not validate a full VPS
installation/reboot, OpenVPN client routing/egress, a domain certificate, ARM64,
future distribution releases or any ISP's reachability. Follow ACCEPTANCE.md.
