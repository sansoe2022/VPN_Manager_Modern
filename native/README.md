# Hysteria v1 lifecycle fix

Upstream: apernet/hysteria v1.3.5, commit
`57c5164854d6cfe00bead730cce731da2babe406` (MIT; see LICENSE-hysteria.md).
Source archive SHA-256:
`9b7961871ebbf5eaa8bbebbd79f08418a6920d004d72f22e4ba0184226b7d215`.

The patch retains the authentication-time address plus a unique per-connection
ID for both connect and disconnect callbacks. Even multiple QUIC connections on
one UDP socket get distinct internal admission keys. Upstream otherwise uses the current QUIC address on disconnect,
which changes during UDP port hopping and leaves a Python admission slot behind.
Accepted authentication also gets a disconnect callback if writing the server hello
fails. No wire protocol, client authentication format or certificates are changed.

Server `idle_timeout` is configurable (4–120 seconds). The standalone core fallback
is 15 seconds; the manager explicitly configures 10 seconds by default and retains
existing saved values. Menu 10 → 09 → 04 changes the saved manager timeout. An app that does
not send QUIC CLOSE on disconnect releases its slot when the server detects idle;
active client keepalives retain the session. A timer never frees a healthy live
connection merely because a wall-clock lease expired.

Build with Go 1.20.14, curl and patch:

```sh
tools/build_udp_core.sh /absolute/output/path
```

Published static binaries use Go 1.20.14 on linux/amd64, CGO disabled, amd64 baseline
and arm64 cross-compilation. The build script verifies the upstream source archive,
uses module go.sum verification and applies this readable patch. Runtime downloads
verify architecture-specific SHA-256 checksums in vpnmanager/udp_runtime.py and
replace the executable atomically before restarting it. User/CA/private keys stay
in their existing files. ARM64 is cross-compiled; native runtime checks use amd64.


The verified runtime assets are hosted in the separate `udp-core-assets-v1.3.5-modern.1`
branch, pinned by immutable asset commit `66c9dc51f97b00e8d7aa8d3283adeef0b6a6c9c1`.
The installer clones the main branch shallowly and downloads only its CPU architecture.
GitHub Release uploads were unavailable for this connection, so runtime URLs use the
ordinary raw repository endpoint with the same SHA-256 verification.
