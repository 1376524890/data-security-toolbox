"""Persist captured file objects independently of whether they trigger DLP."""
from __future__ import annotations

import hashlib
import mimetypes
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import dpkt

from app.core.config import settings
from app.services.dlp.capture import MAX_PACKETS, http_objects, reassemble

MAX_FILES = 500
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
EXPORT_TYPES = ('http', 'ftp-data', 'smb', 'tftp', 'imf')


def object_directory(pcap_id: int) -> Path:
    return settings.storage_dir / 'pcap_objects' / str(pcap_id)


def object_path(pcap_id: int, digest: str) -> Path:
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('invalid object id')
    directory = object_directory(pcap_id).resolve()
    target = (directory / digest).resolve()
    if target.parent != directory:
        raise ValueError('invalid object path')
    return target


def _export(path: Path, directory: Path, protocols: dict, coverage: dict) -> None:
    binary = shutil.which('tshark')
    selected = [name for name in EXPORT_TYPES
                if name in protocols or (name == 'smb' and 'smb2' in protocols)
                or (name == 'imf' and 'smtp' in protocols)]
    if not binary or not selected:
        return
    command = [binary, '-n', '-r', str(path), '-c', str(MAX_PACKETS), '-q']
    for name in selected:
        target = directory / name
        target.mkdir()
        command.extend(['--export-objects', f'{name},{target}'])
    started = time.monotonic()
    with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
        try:
            while True:
                try:
                    process.wait(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    files = [p for p in directory.rglob('*') if p.is_file()]
                    if (len(files) > MAX_FILES
                            or sum(p.stat().st_size for p in files) > MAX_TOTAL_BYTES):
                        coverage['export_limit'] = True
                        break
                    if time.monotonic() - started > 120:
                        coverage['export_timeout'] = True
                        break
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
        if process.returncode:
            coverage['export_incomplete'] = True


def extract_capture_files(path: Path, pcap_id: int, protocols: dict) -> dict[str, Any]:
    directory = object_directory(pcap_id)
    directory.mkdir(parents=True, exist_ok=True)
    objects: dict[str, dict[str, Any]] = {}
    coverage: dict[str, Any] = {'tls_decryption': False, 'packet_limit_count': MAX_PACKETS}
    total = 0

    def retain(body: bytes, metadata: dict) -> None:
        nonlocal total
        if not body:
            return
        digest = hashlib.sha256(body).hexdigest()
        if digest in objects:
            return
        if (len(objects) >= MAX_FILES or len(body) > MAX_FILE_BYTES
                or total + len(body) > MAX_TOTAL_BYTES):
            coverage['object_limit'] = True
            return
        # Filenames from the wire are display labels; storage uses only hashes.
        name = unquote(str(metadata.get('filename') or 'captured-file'))
        name = name.replace('\\', '/').rsplit('/', 1)[-1]
        name = ''.join(c for c in name if ord(c) >= 32)[:255] or 'captured-file'
        target = object_path(pcap_id, digest)
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
            handle.write(body)
            temporary = Path(handle.name)
        try:
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        objects[digest] = {
            **metadata, 'id': digest, 'filename': name, 'size': len(body), 'sha256': digest,
            'mime_type': metadata.get('content_type') or mimetypes.guess_type(name)[0]
            or 'application/octet-stream', 'binary_available': True,
        }
        total += len(body)

    try:
        streams, reassembly = reassemble(path)
        coverage.update(reassembly)
        for key, payload, incomplete in streams:
            for obj in http_objects(payload):
                if obj.get('is_header') or obj.get('is_file') is False:
                    continue
                body = obj.pop('body')
                retain(body, {**obj, 'source': 'http', 'src_ip': key[0], 'src_port': key[1],
                              'dst_ip': key[2], 'dst_port': key[3],
                              'complete': bool(obj.get('complete')) and not incomplete})
    except (ValueError, OSError, EOFError, dpkt.UnpackError) as exc:
        coverage['reassembly_error'] = type(exc).__name__
    # Native exporters cover downloads, FTP, SMB, TFTP and mail attachments.
    # HTTP multipart above also retains client-side uploads and form bodies.
    with tempfile.TemporaryDirectory(prefix='pcap-export-') as temp:
        export_dir = Path(temp)
        try:
            _export(path, export_dir, protocols, coverage)
        except OSError as exc:
            coverage['export_error'] = type(exc).__name__
        for file in sorted(export_dir.rglob('*')):
            if not file.is_file() or file.is_symlink():
                continue
            if file.stat().st_size > MAX_FILE_BYTES:
                coverage['object_limit'] = True
                continue
            body = file.read_bytes()
            # Multipart envelopes are not files; their individual file parts
            # were retained above, without scalar form fields or MIME headers.
            if (file.parent.name == 'http' and body.startswith(b'--')
                    and b'Content-Disposition: form-data' in body[:4096]):
                continue
            retain(body, {'filename': file.name, 'source': file.parent.name, 'complete': None})
    return {'items': list(objects.values()), 'coverage': coverage}


def preview(path: Path, offset: int, limit: int) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open('rb') as handle:
        handle.seek(offset)
        data = handle.read(limit)
    encoding = 'utf-8'
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        encoding = 'gb18030'
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            encoding = 'utf-8 (replacement)'
            text = data.decode('utf-8', errors='replace')
    binary = any(byte < 32 and byte not in (9, 10, 13) for byte in data)
    return {'size': size, 'offset': offset, 'length': len(data), 'hex': data.hex(),
            'text': text, 'encoding': encoding, 'binary': binary,
            'has_more': offset + len(data) < size}
