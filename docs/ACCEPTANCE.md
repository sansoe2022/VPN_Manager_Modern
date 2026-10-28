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
Test fresh-install/URL-restore choices on a real systemd VPS, save the encrypted
backup and its password separately, and verify restored optional services after reboot.
For UDP, check both TCP and UDP data through a Hysteria v1 client using the same
SSH account, and compare its sessions with the shared online API.
Test the selected x-ui installer/panel on its supported Ubuntu version.
Local container verification uses amd64; ARM64 requires its own acceptance run.

For the restored original menu, additionally verify:

- 10 → 00 returns to the first page; 22/35 switch pages; 00 exits from either main page.
- Create a minute-based trial and check expiry/disconnection after the timer runs.
- Set limit 1 in 06 and enable 17. Keep one SSH/OpenVPN/UDP connection active in turn; new connections through all three must be refused while the original remains connected. Disconnect it and confirm another protocol can take its slot. Check simultaneous login attempts and limiter OFF. Lower a mixed account's limit and confirm the newer excess session is removed.
- Test banner display in your chosen SSH app, including HTML if that app supports it.
- Test BadVPN UDP relay through an authenticated SSH client on your network.
- Confirm swap changes affect only the manager's own file and survive a reboot.
- Verify torrent rules/BBR against the actual host kernel and existing firewall policy.
- Test all configured Telegram bot roles with real tokens, including a denied user,
  one-trial-per-day behavior and reseller account ownership/quota limits.
- Verify CheckUser over trusted HTTPS and confirm it discloses only the authenticated account.
