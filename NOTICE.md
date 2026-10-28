# Source and attribution

This project is a source rewrite requested by the owner of
https://github.com/sansoe2022/VPN_Manager (source inspected at commit
`d677313`). The original project references SSHPLUS and @kiritosshxd.
The original repository did not supply a license file at that revision.
No license grant for the original work is asserted here. Legacy binaries, archived
packages and Git history are excluded. At the owner's explicit request, the original
public shared OpenVPN key ZIP is included under vpnmanager/assets; see its README
for provenance and checksum. It is intentionally shared, not a secret unique to a VPS.

The requested UDP integration was compared with sansoe2022/udp at
`57cfdcc44955bb46177dbf42657a5023db2373d8`. Its license loader, SQLite users database,
Redis tracker and opaque manager binary are not included. The integration uses
Hysteria v1.3.5 from apernet/hysteria (source `57c5164854d6cfe00bead730cce731da2babe406`),
with release SHA-256 verification and a new shared-account adapter. Hysteria's
upstream licensing remains applicable: https://github.com/apernet/hysteria/tree/v1.3.5.
Requested x-ui installer provenance/checksums are recorded in vpnmanager/xui.py.
