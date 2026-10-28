"""OpenVPN hook: Unix credentials remain verified by the distribution PAM plugin."""
import os
import sys
import admission


def main():
    host = os.environ.get('trusted_ip6') or os.environ.get('trusted_ip', '')
    port = os.environ.get('trusted_port', '')
    token = ('[' + host + ']' if ':' in host else host) + ':' + port
    if not host or not port.isdigit():
        return 1
    return 0 if admission.request({'action': sys.argv[1], 'protocol': 'openvpn',
        'user': os.environ.get('common_name', ''), 'token': token}) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError):
        sys.exit(1)
