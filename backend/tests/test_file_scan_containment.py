"""One unreadable directory or file must not abort a whole source scan.

The regression this guards: a name that is not valid UTF-8 made the SFTP listing
raise, the scan's top-level handler caught it and finished the run, so everything
after that directory was simply never read - while the result still looked like a
finished scan.
"""
import hashlib
import os
import tempfile
import time
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

    def analyze(path, limits=None):
        # The scan passes its own limits through so the detection budget and the
        # scope cannot disagree; the fake only needs to accept them.
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


PAYLOAD = b'whole-file-payload-that-must-be-hashed-in-full'


class _Instance:
    """Stand-in for the AssetInstance ``ingest.store`` would hand back."""

    def __init__(self, identifier: int) -> None:
        self.id = identifier


def _new_scan(db, name: str, config: dict) -> Task:
    source = FileSource(name=name, protocol='sftp', host='10.0.0.9', port=22,
                        username='root', root_path='/root', password_key_id='k',
                        host_key_sha256='', enabled=True, limits={}, interval_minutes=0,
                        last_status='', last_error='')
    db.add(source)
    db.flush()
    task = Task(kind='file_source_scan', status='Pending',
                payload={'source_id': source.id, 'config': config, 'operation': 'scan'})
    db.add(task)
    db.commit()
    return task


def test_every_file_is_copied_whole_hashed_and_deleted(monkeypatch, tmp_path) -> None:
    """The copy on disk is the whole file, it is hashed in full, then removed.

    The scan must not sample: the operator asked for the whole file, the hash is
    what later proves *which* bytes were seen, and the temporary copy has to be
    gone the moment that hash exists - the disk it lands on is the same one the
    platform needs for its own data.
    """

    class _Remote(_FakeRemote):
        def entries(self, path, check, limit=2000):
            return [('/root/a.txt', 'file', len(PAYLOAD)), ('/root/c.txt', 'file', len(PAYLOAD))]

        def download(self, path, target, consume):
            target.write_bytes(PAYLOAD)
            consume(len(PAYLOAD))

    @contextmanager
    def _connect(config, password):
        yield _Remote()

    monkeypatch.setattr(adapters, 'connect', _connect)
    # Pin the scan's TemporaryDirectory into the test's own dir so leftovers
    # would be visible here instead of in the system /tmp.
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))

    copied: list[int] = []

    def analyze(path, limits=None):
        # Present at analysis time: the download is not streamed away or sampled.
        assert tmp_path in path.parents, 'the scan must copy under the temp root'
        copied.append(len(path.read_bytes()))
        return {'counts': {}, 'hits': [], 'rows': 0, 'coverage': 'complete', 'reason': 'complete'}

    hashes: list[str] = []

    def store(db, source, task, path, size, result, now):
        hashes.append(result['hash'])
        return _Instance(len(hashes)), True, False

    monkeypatch.setattr(scan.ingest, 'analyze', analyze)
    monkeypatch.setattr(scan.ingest, 'store', store)

    with SessionLocal() as db:
        task = _new_scan(db, 'whole-file-source', {**_config(), 'limits': {
            'max_depth': 0, 'max_files': 0, 'max_file_bytes': 0, 'max_bytes': 0, 'max_seconds': 0}})
        result = scan.run(db, task.id)
        db.refresh(task)

    expected = hashlib.sha256(PAYLOAD).hexdigest()
    assert copied and set(copied) == {len(PAYLOAD)}
    assert hashes and set(hashes) == {expected}
    assert result['bytes_read'] == len(PAYLOAD) * result['assets']
    # Nothing survives the run: no content file, and not even the temp dir.
    assert list(tmp_path.iterdir()) == []


def test_a_worker_start_removes_only_abandoned_downloads(monkeypatch, tmp_path) -> None:
    """A killed worker's copy is cleared; a live one's is left alone."""
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    abandoned = tmp_path / f'{scan.TEMP_PREFIX}abandoned'
    abandoned.mkdir()
    (abandoned / 'content.bin').write_bytes(b'leftover')
    live = tmp_path / f'{scan.TEMP_PREFIX}running'
    live.mkdir()
    (live / 'content.bin').write_bytes(b'in flight')
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    old = time.time() - scan.STALE_TEMP_AGE_SECONDS - 60
    os.utime(abandoned, (old, old))

    assert scan.sweep_stale_temp_dirs() == 1
    assert not abandoned.exists()
    assert (live / 'content.bin').read_bytes() == b'in flight'
    assert unrelated.is_dir()
