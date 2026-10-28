# VPN Manager Modern UDP core v1.3.5-modern.1

Static amd64 and arm64 Hysteria v1.3.5 cores with stable, unique admission IDs
across QUIC port migration and a configurable 15-second default idle timeout.

Source, readable patch and reproducible build script:
https://github.com/sansoe2022/VPN_Manager_Modern/tree/75cc9cc/native
https://github.com/sansoe2022/VPN_Manager_Modern/blob/75cc9cc/tools/build_udp_core.sh

Upstream commit: 57c5164854d6cfe00bead730cce731da2babe406. Go 1.20.14, CGO off.
Verify SHA256SUMS before execution. Client wire protocol and credentials are unchanged.
This branch contains only runtime assets; the main branch contains the readable manager.
