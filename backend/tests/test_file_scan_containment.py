"""One unreadable directory or file must not abort a whole source scan.

The regression this guards: a name that is not valid UTF-8 made the SFTP listing
raise, the scan's top-level handler caught it and finished the run, so everything
after that directory was simply never read - while the result still looked like a
finished scan.
"""
from contextlib import contextmanager

from app.core.database import SessionLocal
from app.models import FileSource, Task
from app.services.file_scan import adapters, scan


class _FakeRemote:
    def entries(self, path, check, limit=2000):
        if path == '/root/bad':
            raise UnicodeDecodeError('utf-8', b'\x9d', 0, 1, 'invalid start byte')
        return [('/root/a.txt', 'file', 4), ('/root/bad', 'dir', 0), ('/root/c.txt', 'file', 4)]

    def entries_raw(self, path, check, limit=2000):
        # The fallback also fails here, so the directory is genuinely unreadable.
        raise adapters.SourceError('path_error')

    def download(self, path, target, consume):
        # The scan writes every download to the same temp name, so the payload is
        # what tells the files apart.
        target.write_bytes(b'bad!' if path.endswith('c.txt') else b'data')
        consume(4)


@contextmanager
def _connect(config, password):
    yield _FakeRemote()


def _config() -> dict:
    return {'root_path': '/root', 'limits': {
        'max_depth': 3, 'max_files': 50, 'max_file_bytes': 1024, 'max_bytes': 4096,
        'max_seconds': 30}}


def test_a_bad_directory_and_file_are_reported_but_the_scan_continues(monkeypatch) -> None:
    monkeypatch.setattr(adapters, 'connect', _connect)

    def analyze(path):
        if path.read_bytes() == b'bad!':
            raise UnicodeDecodeError('utf-8', b'\x9d', 0, 1, 'invalid start byte')
        return {'counts': {}, 'hits': [], 'rows': 0, 'coverage': 'complete', 'reason': 'complete'}

    monkeypatch.setattr(scan.ingest, 'analyze', analyze)

    with SessionLocal() as db:
        source = FileSource(name='containment-source', protocol='sftp', host='10.0.0.9', port=22,
                            username='root', root_path='/root', password_key_id='k',
                            host_key_sha256='', enabled=True, limits={}, interval_minutes=0,
                            last_status='', last_error='')
        db.add(source)
        db.flush()
        task = Task(kind='file_source_scan', status='Pending',
                    payload={'source_id': source.id, 'config': _config(), 'operation': 'scan'})
        db.add(task)
        db.commit()
        result = scan.run(db, task.id)
        db.refresh(task)

    assert task.status == 'Partial'
    assert result['complete_scope'] is False
    # Everything else in the tree was still collected: the bad directory did not
    # end the run, and the unreadable file is recorded rather than dropped.
    assert result['assets'] == 2
    paths = {item['path'].rsplit('/', 1)[-1] for item in result['unreadable']}
    assert 'bad' in paths and 'c.txt' in paths
    assert result['unreadable_count'] == 2
