# VPS acceptance checklist

Container checks are not a replacement for a real server test. These checks remain
required on your own VPS and client networks:

- Install on each target systemd OS. Keep a separate administrator SSH session open.
- Configure a managed SSH backend and each needed service; resolve all port conflicts.
- Verify the managed password works through HTTP, framed WebSocket and TLS tunnels.
- Verify unknown users, locked users, expired users and wrong passwords are rejected.
- Verify old sessions stop within one minute of locking/expiry.
- For TLS, install a domain certificate and verify it with a normal client trust store.
- Connect an OpenVPN client, verify DNS and public IPv4 egress, and transfer a large file.
- Confirm client IPv6 is contained according to your own policy; this setup routes IPv4 only.
- Test Squid from an allowed ISP public IP and confirm a disallowed source gets rejected.
- Compare the API total to live authenticated sessions; disconnect and check it falls.
- Reboot, then verify timers, listeners, OpenVPN forwarding/NAT and client connectivity.
- Test from each required ISP; record exact errors and logs for any failed network.
- Verify a config backup can be inspected and restored privately on a spare server.

Record OS version, CPU architecture, OpenVPN/Squid/OpenSSH versions and test date.
Local container verification uses amd64; ARM64 requires its own acceptance run.
