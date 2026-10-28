"""Shared configuration for independent SSH/OpenVPN proxy listeners."""


def listeners(config, configured=False):
    if not configured and 'tunnel' not in config.get('enabled', []):
        return []
    raw = config.get('proxy_listeners')
    if raw is None:
        raw = ([{'port': config.get('tunnel_port', 80),
                 'backends': config.get('proxy_backends', ['ssh', 'openvpn']),
                 'default': config.get('proxy_default_backend', 'ssh')}]
               if 'tunnel' in config.get('enabled', []) else [])
    result, used = [], set()
    for entry in raw:
        number = int(entry['port'])
        backends = list(dict.fromkeys(entry['backends']))
        if not 1 <= number <= 65535 or number in used or not backends or set(backends) - {'ssh', 'openvpn'}:
            raise ValueError('Invalid or duplicate proxy listener configuration.')
        default = entry.get('default', backends[0])
        if default not in backends:
            default = backends[0]
        result.append({'port': number, 'backends': backends, 'default': default})
        used.add(number)
    return result


def port_for(config, backend):
    candidates = [entry for entry in listeners(config) if backend in entry['backends']]
    if not candidates:
        raise ValueError(f'Enable a {backend} WebSocket listener in menu 10 -> 05 first.')
    preferred = config.get('openvpn_client_proxy_port') if backend == 'openvpn' else None
    if preferred is not None:
        for entry in candidates:
            if entry['port'] == int(preferred):
                return entry['port']
    return next((entry['port'] for entry in candidates if entry['default'] == backend), candidates[0]['port'])


def label(entry):
    return ' / '.join('OpenVPN' if item == 'openvpn' else 'SSH' for item in entry['backends']) + ' WebSocket'
