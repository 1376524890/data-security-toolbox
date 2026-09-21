"""Source configuration, encrypted credentials and task snapshots."""
import posixpath
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models import FileSource, Task

from . import credentials
from .adapters import SourceError

FIELDS = ('name', 'protocol', 'host', 'port', 'username', 'root_path', 'host_key_sha256',
          'enabled', 'limits', 'interval_minutes')
DEFAULT_LIMITS = {'max_files': 10000, 'max_depth': 3, 'max_bytes': 67108864,
                  'max_file_bytes': 8388608, 'max_seconds': 120}
CEILINGS = {'max_files': 100000, 'max_depth': 8, 'max_bytes': 536870912,
            'max_file_bytes': 33554432, 'max_seconds': 900}


def serialize(row):
    return {'id': row.id, **{key: getattr(row, key) for key in FIELDS},
            'password_set': bool(row.password_ciphertext), 'last_status': row.last_status,
            'last_error': row.last_error, 'last_scan_at': row.last_scan_at,
            'next_scan_at': row.next_scan_at}


def active(db, source_id):
    return db.scalar(select(Task).where(Task.kind == 'file_source_scan',
        Task.payload['source_id'].as_integer() == source_id,
        Task.status.in_(['Pending', 'Running'])).limit(1))


def save(db, data, row=None):
    if row and active(db, row.id):
        raise SourceError('source_busy')
    protocol = data['protocol']
    if protocol not in {'ftp', 'ftps', 'sftp'}:
        raise SourceError('unsupported_protocol')
    for key in ('host', 'username', 'root_path', 'name'):
        if any(c in data.get(key, '') for c in '\r\n\x00'):
            raise SourceError('invalid_' + key)
    host = data['host'].strip()
    if not host or any(c in host for c in '/@ \\'):
        raise SourceError('invalid_host')
    data = dict(data, host=host, port=data.get('port') or (22 if protocol == 'sftp' else 21))
    root = data.get('root_path', '/')
    if not root.startswith('/') or '..' in root.split('/'):
        raise SourceError('invalid_root_path')
    data['root_path'] = posixpath.normpath(root)
    data['limits'] = {k: max(0 if k == 'max_depth' else 1,
                        min(int((data.get('limits') or {}).get(k, v)), CEILINGS[k]))
                      for k, v in DEFAULT_LIMITS.items()}
    existing = db.scalar(select(FileSource).where(FileSource.name == data['name']))
    if existing and (row is None or existing.id != row.id):
        raise SourceError('name_already_exists')
    # The endpoint identity is what the source name and its collected history
    # describe, so a different host/port/protocol gets a new source. The shared
    # directory may move: paths are stored absolute, so every collected file stays
    # attributable, and a narrower directory only makes the leftovers "not
    # observed" instead of deleting them.
    if row is not None and any(getattr(row, k) != data[k] for k in ('protocol', 'host', 'port')):
        raise SourceError('create_new_source_for_new_target')
    if row is None:
        row = FileSource(**{k: data[k] for k in FIELDS})
        db.add(row)
        db.flush()
    elif row.username != data['username'] and data.get('password') is None:
        raise SourceError('password_required_for_changed_user')
    for key in FIELDS:
        setattr(row, key, data[key])
    if data.get('password') is not None:
        row.password_ciphertext, row.password_nonce, row.password_key_id = credentials.encrypt_password(
            row.id, row.username, data['password'])
    row.next_scan_at = (datetime.now(UTC) + timedelta(minutes=row.interval_minutes)
                        if row.enabled and row.interval_minutes else None)
    db.flush()
    return row


def password(row):
    return credentials.decrypt_password(row.id, row.username, row.password_key_id,
                                        row.password_nonce, row.password_ciphertext)


def remove(db, row):
    """Drop one configuration. Collected assets and evidence are never deleted."""
    if active(db, row.id):
        raise SourceError('source_busy')
    db.delete(row)
    db.flush()


def queue(db, row, operation='scan'):
    # Serialize concurrent manual and scheduled starts on the source row.
    row = db.scalar(select(FileSource).where(FileSource.id == row.id).with_for_update())
    if not row.enabled:
        raise SourceError('source_disabled')
    if active(db, row.id):
        raise SourceError('source_busy')
    config = {key: getattr(row, key) for key in FIELDS}
    task = Task(kind='file_source_scan', payload={'source_id': row.id,
                'operation': operation, 'config': config}, status='Pending')
    db.add(task)
    row.next_scan_at = (datetime.now(UTC) + timedelta(minutes=row.interval_minutes)
                        if row.interval_minutes else None)
    db.flush()
    return task
