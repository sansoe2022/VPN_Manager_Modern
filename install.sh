#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "Installation failed at line $LINENO. Review the error above before retrying." >&2' ERR
[[ ${EUID} -eq 0 ]] || { echo 'Run this installer as root.' >&2; exit 1; }
source /etc/os-release
case "$ID" in
  ubuntu) [[ ${VERSION_ID%%.*} -ge 20 ]] || { echo 'Ubuntu 20.04 or later is required.' >&2; exit 1; } ;;
  debian) [[ ${VERSION_ID%%.*} -ge 12 ]] || { echo 'Debian 12 or later is required.' >&2; exit 1; } ;;
  *) echo 'Only Ubuntu 20.04+ and Debian 12+ are supported.' >&2; exit 1 ;;
esac
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ -f "$src/vpnmanager/manager.py" ]] || { echo 'Clone the complete repository before running install.sh.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd server is required.' >&2; exit 1; }
# An old installation can own the same ports, cron jobs and accounts. Do not overwrite it.
if [[ -d /etc/SSHPlus || -d /etc/VPNManager ]]; then
  echo 'Legacy installation detected. Use a fresh server; see docs/MIGRATION.md.' >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
apt-get -o Acquire::Retries=3 update
apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3 openssh-server openssl ca-certificates iproute2 procps squid stunnel4 openvpn easy-rsa iptables util-linux
install -d -m 0755 /usr/local/lib/vpnmanager
install -m 0644 "$src"/vpnmanager/*.py /usr/local/lib/vpnmanager/
install -d -m 0755 /usr/local/lib/vpnmanager/assets
install -m 0644 "$src/vpnmanager/assets/openvpn-shared.zip" /usr/local/lib/vpnmanager/assets/
install -d -m 0755 /usr/local/lib/vpnmanager/Modulos
install -m 0755 "$src"/Modulos/* /usr/local/lib/vpnmanager/Modulos/
install -d -m 0700 /etc/vpnmanager /var/lib/vpnmanager /var/lib/vpnmanager/backups
cat > /usr/local/bin/vpnmanager <<'WRAPPER'
#!/usr/bin/env bash
exec python3 -B /usr/local/lib/vpnmanager/manager.py "$@"
WRAPPER
chmod 0755 /usr/local/bin/vpnmanager
for alias in menu vpnmenu; do
  if [[ -e /usr/local/bin/$alias && ! -L /usr/local/bin/$alias ]]; then
    cp -an "/usr/local/bin/$alias" "/var/lib/vpnmanager/backups/$alias.before-install"
  fi
  ln -sfn /usr/local/bin/vpnmanager "/usr/local/bin/$alias"
done
vpnmanager initialize
for service in vpnmanager-tunnel vpnmanager-online; do
  if systemctl is-active --quiet "$service"; then
    systemctl restart "$service"
  fi
done
printf '\nInstallation complete. Run: sudo vpnmanager\n'
printf 'Original SSHPlus numbering is restored. Connection mode: 10; back: 00; more: 22.\n'
