"""Bounded, unprivileged TCP inventory executed on the probe host."""
from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

COMMON_PORTS = {21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
                139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb', 1433: 'mssql',
                1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
                5672: 'amqp', 6379: 'redis', 8080: 'http', 8443: 'https', 9200: 'elasticsearch', 27017: 'mongodb'}


def expand_targets(targets, max_hosts=256):
    if not targets:
        raise ValueError('Explicit scan targets are required')
    limit = min(max(int(max_hosts), 1), 1024)
    hosts = set()
    for target in targets:
        network = ipaddress.ip_network(str(target).strip(), strict=False)
        if network.num_addresses > limit + 2:
            raise ValueError(f'Target exceeds max_hosts={limit}')
        for address in network.hosts():
            if address.is_multicast or address.is_unspecified:
                raise ValueError('Multicast and unspecified addresses are not scan targets')
            hosts.add(str(address))
            if len(hosts) > limit:
                raise ValueError(f'Targets exceed max_hosts={limit}')
    return sorted(hosts)


def inspect_port(host, port, timeout):
    service = COMMON_PORTS.get(port, 'unknown')
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            row = {'ip': host, 'port': port, 'protocol': 'tcp', 'service': service, 'banner': ''}
            if service == 'https':
                # This is certificate observation, not an authenticated application connection.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        row['tls'] = {'version': tls.version(), 'cipher': tls.cipher()[0]}
                except (OSError, ssl.SSLError):
                    pass
            elif service in {'http', 'elasticsearch'}:
                try:
                    sock.sendall(f'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n'.encode())
                    row['banner'] = sock.recv(1024).decode('utf-8', 'replace')[:1024]
                except OSError:
                    pass
            elif service in {'ssh', 'ftp', 'smtp', 'pop3', 'imap', 'mysql'}:
                try:
                    row['banner'] = sock.recv(1024).decode('utf-8', 'replace')[:1024]
                except OSError:
                    pass
            return row
    except OSError:
        return None


def scan_network(config, stop_event=None):
    hosts = expand_targets(config.get('targets', []), config.get('max_hosts', 256))
    ports = sorted(set(int(p) for p in config.get('ports', COMMON_PORTS)))
    if not ports or len(ports) > 256 or any(p < 1 or p > 65535 for p in ports):
        raise ValueError('Configure 1..256 TCP ports in range 1..65535')
    timeout = min(max(float(config.get('connect_timeout', .5)), .1), 3)
    deadline = time.monotonic() + min(max(int(config.get('timeout_seconds', 120)), 1), 600)
    rows, completed = [], 0
    def work(pair):
        if time.monotonic() >= deadline or (stop_event and stop_event.is_set()):
            return False, None
        return True, inspect_port(*pair, timeout)
    with ThreadPoolExecutor(max_workers=min(max(int(config.get('concurrency', 32)), 1), 64)) as pool:
        # Host/port limits also bound the submitted work queue.
        for future in as_completed([pool.submit(work, (host, port)) for host in hosts for port in ports]):
            attempted, row = future.result()
            completed += int(attempted)
            if row:
                rows.append(row)
    return {'assets': rows, 'targets': config['targets'], 'scanned_hosts': hosts,
            'ports': ports, 'completed_checks': completed, 'total_checks': len(hosts) * len(ports),
            'complete': completed == len(hosts) * len(ports), 'observed_at': datetime.now(UTC).isoformat(),
            'scanner': 'tcp-connect', 'location': 'probe'}
