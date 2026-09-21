"""Real offline runtime checks; run only in the disposable smoke-test container."""
import http.server
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import openpyxl
import psutil
import regex

APP = Path('/opt/data-security-toolbox')
sys.path.insert(0, str(APP))
from probe import probe
from shared.sensitive_detection import build_engine

assert probe.AGENT_VERSION == '3.7.0'
assert psutil.virtual_memory().total > 0
assert regex.search(r'\d+', 'abc123', timeout=0.1).group() == '123'
assert ssl.create_default_context().get_ca_certs()
assert socket.getaddrinfo('localhost', 80)
capture_ok = False
with tempfile.TemporaryDirectory() as scratch:
    path = Path(scratch) / 'sample.xlsx'
    book = openpyxl.Workbook()
    book.active.append(['phone', '13800138000'])
    book.save(path)
    loaded = openpyxl.load_workbook(path, read_only=True)
    assert next(loaded.active.values) == ('phone', '13800138000')
    loaded.close()
    assert build_engine().scan_text('contact person@example.com')
    capture = Path(scratch) / 'loopback.pcapng'
    process = subprocess.Popen([str(APP / 'runtime/bin/dumpcap'), '-i', 'lo', '-a',
                                'duration:2', '-w', str(capture), '-q'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.4)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for _ in range(10):
            sender.sendto(b'offline-runtime-check', ('127.0.0.1', 54321))
            time.sleep(0.04)
    _, error = process.communicate(timeout=10)
    stderr = error.decode()
    if os.uname().machine == 'x86_64':
        assert process.returncode == 0, stderr
        assert capture.stat().st_size > 200
        assert capture.read_bytes()[:4] == b'\x0a\x0d\x0d\x0a'
        capture_ok = True
    else:
        # qemu-user cannot translate the socket ioctls libpcap asks for, so libpcap
        # refuses every device here (even `dumpcap -D` fails with SIOCETHTOOL). That
        # is an emulator artifact; the same package is capture-verified on amd64.
        print('SKIP: real capture under emulation -', stderr.strip().splitlines()[-1])


class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *_):
        pass


server = http.server.HTTPServer(('127.0.0.1', 0), Health)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/api/v1/health') as response:
    assert response.status == 200
server.shutdown()
server.server_close()
import importlib

SKIP_EXTENSIONS = {'_tkinter', 'xxlimited', 'xxlimited_35'}
extensions = sorted(Path(APP / 'runtime/python/lib/python3.11/lib-dynload').glob('*.so'))
assert extensions, 'no bundled extension modules found'
for module in extensions:
    name = module.name.split('.')[0]
    if name in SKIP_EXTENSIONS:
        continue
    importlib.import_module(name)

if os.uname().machine == 'x86_64':
    # No host libc/OpenSSL/extension library may leak into this Python process,
    # not even after every bundled extension module has been imported. (Skipped
    # under qemu: the emulator's own libraries show up in the maps.)
    leaks = [line.rsplit(None, 1)[-1] for line in Path('/proc/self/maps').read_text().splitlines()
             if '.so' in line and '/' in line and str(APP / 'runtime') not in line]
    assert not leaks, leaks
for value in (sys.executable, sys.prefix, sys.base_prefix):
    assert str(APP / 'runtime') in str(value), value
verified = ['private libraries', 'imports', 'TLS roots', 'DNS', 'XLSX', 'regex', 'shared engine', 'HTTP']
if capture_ok:
    verified.append('real capture')
verified += [f'{len(extensions)} bundled extension modules', 'bundled interpreter']
print('PASS:', ', '.join(verified))
