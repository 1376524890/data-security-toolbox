"""Import Grype v6 SQLite/archive data into the local CVE catalog atomically."""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
import time
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import zstandard
from sqlalchemy import select

from app.core.config import settings
from app.models import LocalCve, OfflineResource

LATEST = 'https://grype.anchore.io/databases/v6/latest.json'
MAX_ARCHIVE = 2 * 1024 ** 3
MAX_DATABASE = 12 * 1024 ** 3


@contextmanager
def import_lock():
    path = settings.integration_dir / 'grype-import.lock'
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open('a+b')
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0)
            if not handle.read(1):
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        yield
    except OSError as exc:
        if not locked:
            raise ValueError('已有 Grype 导入任务运行中') from exc
        raise
    finally:
        if locked and os.name == 'nt':
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        handle.close()  # The OS releases this lock even after a process crash.


def download_latest(directory, progress=lambda **kw: None):
    response = requests.get(LATEST, timeout=(10, 60))
    response.raise_for_status()
    metadata = response.json()
    if not str(metadata.get('schemaVersion', '')).lstrip('v').startswith('6'):
        raise ValueError('仅支持 Grype DB v6')
    url = urljoin(LATEST, metadata.get('url') or metadata['path'])
    if urlparse(url).scheme != 'https' or urlparse(url).hostname != 'grype.anchore.io':
        raise ValueError('Grype 数据库地址不属于官方源')
    digest, size, last = hashlib.sha256(), 0, time.monotonic()
    archive = Path(directory) / 'grype.tar.zst'
    with requests.get(url, stream=True, timeout=(15, 90)) as response:
        response.raise_for_status()
        with archive.open('wb') as output:
            for chunk in response.iter_content(1024 * 1024):
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise ValueError('Grype 压缩包超过 2 GB 限制')
                digest.update(chunk)
                output.write(chunk)
                if time.monotonic() - last > 2:
                    progress(stage='downloading', downloaded_bytes=size)
                    last = time.monotonic()
    if metadata.get('checksum') != 'sha256:' + digest.hexdigest():
        raise ValueError('Grype DB SHA256 校验失败')
    return archive, metadata


def extract_database(source, directory):
    source = Path(source)
    target = Path(directory) / 'vulnerability.db'
    with source.open('rb') as handle:
        signature = handle.read(16)
    if signature == b'SQLite format 3\x00':
        if source.stat().st_size > MAX_DATABASE:
            raise ValueError('数据库超过 12 GB 限制')
        shutil.copyfile(source, target)
        return target
    with source.open('rb') as handle:
        stream = zstandard.ZstdDecompressor().stream_reader(handle) if signature[:4] == b'\x28\xb5\x2f\xfd' else handle
        try:
            with tarfile.open(fileobj=stream, mode='r|*') as archive:
                found, total = False, 0
                for member in archive:
                    total += member.size
                    if total > MAX_DATABASE or member.issym() or member.islnk() or '..' in Path(member.name).parts or member.name.startswith(('/', '\\')):
                        raise ValueError('不安全或过大的数据库归档')
                    if Path(member.name).name != 'vulnerability.db':
                        continue
                    if found or not member.isfile():
                        raise ValueError('数据库文件重复或类型无效')
                    with archive.extractfile(member) as incoming, target.open('wb') as output:
                        shutil.copyfileobj(incoming, output, length=1024 * 1024)
                    found = True
                if not found:
                    raise ValueError('归档不包含 vulnerability.db（需要 Grype v6）')
        finally:
            if stream is not handle:
                stream.close()
    return target


def score_from_blob(blob):
    from cvss import CVSS2, CVSS3, CVSS4
    scores = []
    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() in {'basescore', 'base_score'} and isinstance(item, (int, float)) and 0 <= item <= 10:
                    scores.append(float(item))
                elif key == 'vector' and isinstance(item, str):
                    try:
                        calculator = CVSS4 if item.startswith('CVSS:4') else CVSS3 if item.startswith('CVSS:3') else CVSS2
                        scores.append(float(calculator(item).scores()[0]))
                    except Exception:
                        pass  # Upstream occasionally supplies incomplete vectors.
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(blob.get('severities', blob.get('severity', {})))
    return max(scores, default=0.0)


def grype_records(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as database:
        database.execute('PRAGMA query_only=ON')
        database.execute('PRAGMA trusted_schema=OFF')
        if database.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('Grype SQLite 完整性检查失败')
        tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'vulnerability_handles', 'blobs', 'db_metadata'}.issubset(tables):
            raise ValueError('不是受支持的 Grype v6 数据库')
        if database.execute('SELECT model FROM db_metadata LIMIT 1').fetchone()[0] != 6:
            raise ValueError('仅支持 Grype DB schema v6')
        # Prefer NVD when multiple providers describe the same CVE; stream rows.
        query = """SELECT v.name, v.published_date, v.modified_date, b.value
                   FROM vulnerability_handles v JOIN blobs b ON v.blob_id=b.id
                   WHERE v.name LIKE 'CVE-%'
                   ORDER BY v.name, CASE WHEN v.provider_id='nvd' THEN 0 ELSE 1 END, v.provider_id"""
        previous = None
        for name, published, modified, raw in database.execute(query):
            if name == previous or not re.fullmatch(r'CVE-\d{4}-\d{4,}', name):
                continue
            previous = name
            blob = json.loads(raw)
            score = score_from_blob(blob)
            severity = 'Critical' if score >= 9 else 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low' if score else 'Unknown'
            yield {'cve_id': name, 'source': 'grype', 'severity': severity, 'cvss_score': score,
                   'published': published or '', 'modified': modified or '',
                   'description': {'text': blob.get('description', ''), 'grype': blob}}


def import_database(db, source, metadata=None, progress=lambda **kw: None):
    metadata = metadata or {}
    with tempfile.TemporaryDirectory(dir=settings.integration_dir) as work:
        progress(stage='extracting')
        database = extract_database(source, work)
        with closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as native:
            native.execute('PRAGMA trusted_schema=OFF')
            cursor = native.execute('SELECT * FROM db_metadata LIMIT 1')
            row = cursor.fetchone()
            if row is None:
                raise ValueError('Grype DB 缺少版本元数据')
            native_metadata = dict(zip((column[0] for column in cursor.description), row))
        metadata = {**metadata, 'schemaVersion': f"v{native_metadata['model']}.{native_metadata.get('revision', 0)}.{native_metadata.get('addition', 0)}",
                    'built': native_metadata.get('build_timestamp') or metadata.get('built') or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        existing = {name: (identifier, origin) for identifier, name, origin in db.execute(select(LocalCve.id, LocalCve.cve_id, LocalCve.source))}
        additions, changes, imported, updated, preserved = [], [], 0, 0, 0
        try:
            for record in grype_records(database):
                old = existing.get(record['cve_id'])
                if old and old[1] != 'grype':
                    preserved += 1  # User/other-source records are not overwritten.
                    continue
                if old:
                    changes.append({'id': old[0], **record})
                    updated += 1
                else:
                    additions.append(record)
                    imported += 1
                if len(additions) + len(changes) >= 1000:
                    if additions:
                        db.bulk_insert_mappings(LocalCve, additions)
                    if changes:
                        db.bulk_update_mappings(LocalCve, changes)
                    additions, changes = [], []
                    progress(stage='importing', imported=imported, updated=updated)
            if not imported + updated + preserved:
                raise ValueError('Grype DB 中没有 CVE 条目')
            if additions:
                db.bulk_insert_mappings(LocalCve, additions)
            if changes:
                db.bulk_update_mappings(LocalCve, changes)
            resource = db.scalar(select(OfflineResource).where(OfflineResource.resource_type == 'grype_db', OfflineResource.name == 'Grype DB'))
            if not resource:
                resource = OfflineResource(resource_type='grype_db', name='Grype DB')
                db.add(resource)
            old_path = Path(resource.storage_path) if resource.storage_path else None
            resource.version = metadata['schemaVersion'] + ' / ' + str(metadata['built'])
            resource.count = imported + updated + preserved
            resource.status = 'imported'
            resource.resource_metadata = {**metadata, 'imported': imported, 'updated': updated, 'preserved': preserved, 'schema': 6}
            # Retain native package/CPE data for external Grype tooling as well.
            destination = settings.integration_dir / 'grype' / (hashlib.sha256((resource.version + str(time.time_ns())).encode()).hexdigest()[:24] + '.db')
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(database, destination)
            resource.storage_path = str(destination)
            db.commit()
            if old_path and old_path.resolve().parent == destination.resolve().parent and old_path != destination:
                try:
                    old_path.unlink(missing_ok=True)
                except OSError:
                    pass  # A reader may still have the previous snapshot open.
        except Exception:
            db.rollback()
            raise
        return {'imported': imported, 'updated': updated, 'preserved': preserved, 'version': resource.version}
