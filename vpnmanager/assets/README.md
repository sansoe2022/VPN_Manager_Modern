# Original shared OpenVPN bundle

`openvpn-shared.zip` is an exact copy of the intentionally public
`Install/master-keys.zip` from sansoe2022/VPN_Manager at commit
`d6773130559c10752ebb50ffddd054e7077e432c`, included at the owner's explicit request.

SHA256: `2819e194803280f07e17f6f16390d104c35736fca1312267efa19a9d22e2e194`.
The server private key is shared/public, not unique to a VPS. Certificates expire
in May 2036. The loader verifies the checksum and certificate chain, and imports
only fixed filenames. Client exports contain the CA and tls-auth key, not the
server private key. Original binaries and other bundled installers remain excluded.
