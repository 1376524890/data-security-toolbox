"""Source configuration, encrypted credentials and task snapshots."""
import posixpath
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models import FileSource, Task

from . import credentials
from .adapters import SourceError

FIELDS = ('name', 'protocol', 'host', 'port', 'username', 'root_path', 'host_key_sha256',
          'enabled', 'limits', 'interval_minutes')
#: Coverage contract for one shared-file source. Every key follows one rule:
#: 0 means "no limit", so a check task can be told to read a whole share; a
#: non-zero value is the operator's own cap, clamped to ``CEILINGS`` so a typo
#: cannot ask for something absurd.
#:
#: The floor used to be 1 for every key except max_depth, which silently turned
#: the documented "0 = no time limit" into a one-second run: every check task
#: ended "Partial / time_budget" after reading a handful of files. Defaults are
#: 0 here (unlimited) and the scan honours 0 as unlimited for all five keys.
DEFAULT_LIMITS = {'max_files': 0, 'max_depth': 0, 'max_bytes': 0,
                  'max_file_bytes': 0, 'max_seconds': 0}
CEILINGS = {'max_files': 100000, 'max_depth': 64, 'max_bytes': 100 * 1024 ** 3,
            'max_file_bytes': 10 * 1024 ** 3, 'max_seconds': 31536000}

#: Where the exclusion list is kept inside the ``limits`` JSON column. It lives
#: there rather than in a column of its own because the shape is per-source
#: configuration exactly like the numeric limits, and adding a column would need
#: a migration for a list nobody queries in SQL.
EXCLUDE_KEY = 'exclude_paths'

#: Directories whose contents are *third-party code*, never the checked
#: organisation's own data. Scanning them produced most of this platform's false
#: positives in practice: of 954 sensitive-data detections on one host, 403 came
#: from ``node_modules`` and ``site-packages`` - a password parameter name in a
#: pip wheel, an 11-digit codepoint array in ``idnadata.py`` counted as a phone
#: number, a Luhn-passing constant in a minified JS file counted as a bank card.
#:
#: Only unambiguous dependency and cache stores are listed. Generic build output
#: (``dist``/``build``/``bin``/``target``/``obj``) is deliberately *not* excluded
#: by default: those names are common in an organisation's own tree and may hold
#: real configuration, so dropping them silently would trade a false positive for
#: a missed one. An operator adds them per source when they want that.
DEFAULT_EXCLUDES = (
    '.git', '.hg', '.svn',
    'node_modules', 'bower_components', '.next', '.nuxt', '.angular', '.vite',
    '__pycache__', 'site-packages', 'dist-packages', '.venv', 'venv', 'virtualenv',
    '.tox', '.eggs', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.ipynb_checkpoints',
    '.cargo', '.rustup', '.npm', '.yarn', '.gradle', '.m2', '.conda', '.pyenv', '.nvm',
)


def _normalize_excludes(values):
    """Paths/names that may be excluded, refusing anything that walks upwards."""
    cleaned = []
    for value in values or []:
        item = str(value).strip()
        if not item or len(item) > 512 or '\x00' in item:
            continue
        # A leading ``/`` is what makes an entry name one subtree instead of any
        # directory with that name, so it has to survive normalization; the
        # trailing separators carry no meaning and are dropped.
        absolute = item.startswith('/')
        item = item.strip('/')
        if not item:
            continue
        if '..' in item.split('/'):
            continue
        if absolute:
            item = '/' + item
        if item not in cleaned:
            cleaned.append(item)
    return cleaned


def excludes_for(row) -> list[str]:
    """The exclusion list a scan of this source will actually use.

    An empty stored list means "the platform default", which keeps a source
    created before this option existed on the safe side of the trade-off without
    rewriting anyone's configuration. An operator who really wants a dependency
    tree scanned sets the list to exactly that.
    """
    stored = _normalize_excludes((row.limits or {}).get(EXCLUDE_KEY))
    return stored if stored else list(DEFAULT_EXCLUDES)


def path_excluded(path: str, excludes: list[str]) -> bool:
    """A bare name excludes that directory anywhere; an absolute path one subtree."""
    for entry in excludes:
        if entry.startswith('/'):
            if path == entry:
                return True
        elif path.rsplit('/', 1)[-1] == entry:
            return True
    return False


def serialize(row):
    """One source as the console reads it.

    ``limits`` stays a flat numeric map - the console formats every entry as a
    coverage limit - so the exclusion list is lifted out of that column and
    returned as its own field, next to the list the walk will really apply.
    """
    limits = row.limits or {}
    stored_excludes = _normalize_excludes(limits.get(EXCLUDE_KEY))
    numeric = {key: value for key, value in limits.items() if key != EXCLUDE_KEY}
    return {'id': row.id, **{key: getattr(row, key) for key in FIELDS if key != 'limits'},
            'limits': numeric, 'exclude_paths': stored_excludes,
            'effective_exclude_paths': excludes_for(row),
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
    # 0 = "no limit" for every key, so it must survive normalization; only a
    # non-zero value is clamped to its ceiling.
    data['limits'] = {k: max(0, min(int((data.get('limits') or {}).get(k, v)), CEILINGS[k]))
                      for k, v in DEFAULT_LIMITS.items()}
    # Exclusions ride in the same JSON column the numeric limits use, because
    # they are per-source scan configuration and do not deserve a migration.
    # Only a non-empty list is written: an absent key and an empty one both mean
    # "use the platform default" (see ``excludes_for``), and storing ``[]`` would
    # rewrite the limits of every existing source for no gain.
    excludes = _normalize_excludes(data.get('exclude_paths'))
    if excludes:
        data['limits'][EXCLUDE_KEY] = excludes
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
    # Freeze the effective list into the task, so a later edit of the source
    # cannot change what a queued scan was told to skip.
    config['limits'] = {**(config.get('limits') or {}), EXCLUDE_KEY: excludes_for(row)}
    task = Task(kind='file_source_scan', payload={'source_id': row.id,
                'operation': operation, 'config': config}, status='Pending')
    db.add(task)
    row.next_scan_at = (datetime.now(UTC) + timedelta(minutes=row.interval_minutes)
                        if row.interval_minutes else None)
    db.flush()
    return task
