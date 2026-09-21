"""A global bound stops the scan; it is never recorded as unreadable content.

The regression this guards: the per-item handlers that keep a bad directory or
file from aborting the scan must not also swallow ``time_budget`` / ``cancelled``
/ ``byte_budget`` — those arrive from the same ``check()`` and mean "stop", so
swallowing them kept the scan running and filled ``unreadable`` with thousands
of entries that were never actually tried.
"""
from contextlib import contextmanager

from app.core.database import SessionLocal
from app.models import FileSource, Task
from app.services.file_scan import adapters, scan


class _TimeBudgetRemote:
    def entries(self, path, check, limit=2000):
        check()  # raises the moment the scan is out of time
        return [('/root/a.txt', 'file', 4)]

    def entries_raw(self, path, check, limit=2000):
        check()
        return []

    def download(self, path, target, consume):  # pragma: no cover - never reached
        raise AssertionError('nothing should be downloaded after the budget stops')


@contextmanager
def _connect(config, password):
    yield _TimeBudgetRemote()


def test_time_budget_stops_the_scan_without_marking_content_unreadable(monkeypatch) -> None:
    monkeypatch.setattr(adapters, 'connect', _connect)

    with SessionLocal() as db:
        source = FileSource(name='budget-source', protocol='sftp', host='10.0.0.9', port=22,
                            username='root', root_path='/root', password_key_id='k',
                            host_key_sha256='', enabled=True, limits={}, interval_minutes=0,
                            last_status='', last_error='')
        db.add(source)
        db.flush()
        task = Task(kind='file_source_scan', status='Pending',
                    payload={'source_id': source.id, 'operation': 'scan', 'config': {
                        'root_path': '/root', 'limits': {
                            'max_depth': 3, 'max_files': 10000, 'max_file_bytes': 1024,
                            'max_bytes': 4096, 'max_seconds': 0}}})
        db.add(task)
        db.commit()
        result = scan.run(db, task.id)
        db.refresh(task)

    assert result['termination_reason'] == 'time_budget'
    assert result['unreadable_count'] == 0
