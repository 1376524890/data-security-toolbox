"""Shared-file transport and lifecycle tests use isolated fixtures only."""
import socket
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import AssetInstance, FileSource
from app.services.file_scan import adapters, scan, service


def config(name='shared-fixture'):
    return dict(name=name, protocol='ftp', host='files.invalid', port=21, username='reader',
                password='never-return-this', root_path='/share', host_key_sha256='', enabled=True,
                limits={}, interval_minutes=15)


def test_password_encrypted_and_task_snapshot_has_no_secret():
    with SessionLocal() as db:
        row = service.save(db, config())
        assert row.password_ciphertext and b'never-return-this' not in row.password_ciphertext
        assert service.password(row) == 'never-return-this'
        response = service.serialize(row)
        assert 'password' not in response and response['password_set']
        task = service.queue(db, row)
        assert 'never-return-this' not in str(task.payload)
        with pytest.raises(adapters.SourceError, match='source_busy'):
            service.queue(db, row)
        db.rollback()


def test_empty_limits_mean_no_limit_and_survive_normalization():
    """0 must stay "no limit" for every coverage knob.

    The regression this guards: the normalizer floored every key but max_depth at
    1, so a check task queued with ``limits: {}`` (what the console sends) was
    stored with ``max_seconds: 1`` and stopped after one second - every run ended
    "Partial / time_budget" after a handful of files.
    """
    with SessionLocal() as db:
        row = service.save(db, config('unlimited-source'))
        assert row.limits == {'max_files': 0, 'max_depth': 0, 'max_bytes': 0,
                              'max_file_bytes': 0, 'max_seconds': 0}
        # An explicit cap is still stored as asked, and an explicit 0 stays 0.
        capped = service.save(db, dict(config('capped-source'),
                                       limits={'max_seconds': 120, 'max_files': 5}))
        assert capped.limits['max_seconds'] == 120 and capped.limits['max_files'] == 5
        zeroed = service.save(db, dict(config('zeroed-source'), limits={'max_seconds': 0,
                                                                        'max_depth': 0}))
        assert zeroed.limits['max_seconds'] == 0 and zeroed.limits['max_depth'] == 0
        db.rollback()


def test_read_only_scan_persists_membership_and_cleans_temporary_files(monkeypatch):
    paths = []
    remote = Mock()
    remote.entries.return_value = [('/share/contact.txt', 'file', 24)]
    def download(path, target, consume):
        data = b'contact ops@example.org\n'
        consume(len(data))
        target.write_bytes(data)
        paths.append(target)
    remote.download.side_effect = download
    @contextmanager
    def connect(*args):
        yield remote
    monkeypatch.setattr(adapters, 'connect', connect)
    with SessionLocal() as db:
        row = service.save(db, config('shared-run'))
        task = service.queue(db, row)
        db.commit()
        result = scan.run(db, task.id)
        assert result['assets'] == 1
        assert result['new'] == 1
        assert result['sensitive'] == 1
        instance = db.get(AssetInstance, result['asset_instance_ids'][0])
        assert instance.path == '/share/contact.txt'
        assert instance.source_kind == 'file_share'
        assert instance.owner_key == f'file-source:{row.id}'
        assert all(not p.exists() for p in paths)
        second = service.queue(db, row)
        db.commit()
        again = scan.run(db, second.id)
        assert again['new'] == 0 and again['changed'] == 0
        assert again['asset_instance_ids'] == result['asset_instance_ids']
    with TestClient(app) as client:
        body = client.get('/api/v1/asset-instances', params={'task_id': task.id}).json()
        assert body['total'] == 1
        assert body['association'] == 'recorded_membership'
        # The detail page must name this collector: a shared file source has no
        # probe row, so an empty source would read as "came from nowhere".
        detail = client.get(f"/api/v1/asset-instances/{result['asset_instance_ids'][0]}").json()
        assert detail['source_kind'] == 'file_share'
        assert detail['owner_key'] == f'file-source:{row.id}'
        assert detail['source_name'] == 'shared-run'
        assert detail['host'] == 'files.invalid'
        assert detail['probe_id'] is None and detail['probe_name'] == ''


def test_failed_connection_is_terminal_without_password_echo(monkeypatch):
    @contextmanager
    def connect(*args):
        raise RuntimeError('server echoed never-return-this')
        yield
    monkeypatch.setattr(adapters, 'connect', connect)
    with SessionLocal() as db:
        row = service.save(db, config('shared-fail'))
        task = service.queue(db, row)
        db.commit()
        result = scan.run(db, task.id)
        assert task.status == 'Failed'
        assert not result['complete_scope']
        assert 'never-return-this' not in task.error


def test_a_root_that_cannot_be_listed_is_never_a_complete_scope(monkeypatch):
    """A missing root must not read as "Success / 0 files".

    The regression this guards: an unlistable directory was only counted as
    skipped while ``complete`` stayed true, so a check task pointed at a path the
    host does not have reported success with no assets - and a complete scope is
    exactly what lets the platform mark every instance it had seen NOT_OBSERVED.
    """
    remote = Mock()
    remote.entries.side_effect = adapters.SourceError('unreadable_root')
    remote.entries_raw.side_effect = adapters.SourceError('unreadable_root')

    @contextmanager
    def connect(*args):
        yield remote

    monkeypatch.setattr(adapters, 'connect', connect)
    with SessionLocal() as db:
        row = service.save(db, config('missing-root'))
        task = service.queue(db, row)
        db.commit()
        result = scan.run(db, task.id)
        assert result['assets'] == 0
        assert result['complete_scope'] is False
        assert result['termination_reason'] == 'unreadable'
        assert result['unreadable'] == [{'path': '/share', 'reason': 'SourceError',
                                        'fallback': 'SourceError'}]
        db.refresh(task)
        assert task.status == 'Failed'


@pytest.mark.parametrize('name', ['..', '/etc/passwd', 'a/b', 'a\\b', 'bad\r\nRETR x'])
def test_remote_names_cannot_escape_the_selected_directory(name):
    with pytest.raises(adapters.SourceError):
        adapters.child_path('/share', name)


def test_the_shared_directory_can_move_but_the_endpoint_cannot():
    """An operator narrows a share without losing history; the host is fixed."""
    with SessionLocal() as db:
        row = service.save(db, config('shared-edit'))
        moved = service.save(db, dict(config('shared-edit'), root_path='/share/sub/'), row)
        assert moved.id == row.id and moved.root_path == '/share/sub'
        for field, value in [('host', 'other.invalid'), ('port', 2121), ('protocol', 'sftp')]:
            with pytest.raises(adapters.SourceError, match='create_new_source_for_new_target'):
                service.save(db, dict(config('shared-edit'), **{field: value}), row)
        db.rollback()


def test_a_source_can_be_removed_but_not_while_it_is_collecting(monkeypatch):
    with SessionLocal() as db:
        row = service.save(db, config('shared-delete'))
        task = service.queue(db, row)
        db.commit()
        with pytest.raises(adapters.SourceError, match='source_busy'):
            service.remove(db, row)
        task.status = 'Success'
        db.commit()
        service.remove(db, row)
        db.commit()
        assert db.get(FileSource, row.id) is None


def test_ftp_and_ftps_never_use_write_commands(monkeypatch, tmp_path):
    client = Mock()
    client.retrlines.side_effect = lambda command, callback: callback('type=file;size=3; a.txt')
    client.retrbinary.side_effect = lambda command, callback, **kw: callback(b'abc')
    monkeypatch.setattr(adapters.ftplib, 'FTP', Mock(return_value=client))
    monkeypatch.setattr(adapters.ftplib, 'FTP_TLS', Mock(return_value=client))
    for protocol in ['ftp', 'ftps']:
        with adapters.connect(dict(config(), protocol=protocol), 'secret') as remote:
            assert list(remote.entries('/share', lambda: None)) == [('/share/a.txt', 'file', 3)]
            remote.download('/share/a.txt', tmp_path/'out.txt', lambda n: None)
        assert not client.storbinary.called
        assert not client.delete.called
        assert not client.rename.called
    client.prot_p.assert_called_once()


def test_ftp_falls_back_to_list_when_mlsd_is_missing(monkeypatch):
    """vsftpd 3.0.5 answers ``500`` to MLSD; the share must still be listable."""
    client = Mock()
    listing = [
        'total 5',
        'drwxr-xr-x    2 0        0            4096 Sep 20 03:00 pub',
        '-rw-r--r--    1 0        0              12 Sep 15 22:02 report 2026.csv',
        'lrwxrwxrwx    1 0        0               7 Jun 16 06:14 bin -> usr/bin',
        'crw-rw-rw-    1 0        0         1, 3 Sep 20 03:00 null',
    ]

    def retrlines(command, callback):
        if command.startswith('MLSD'):
            raise adapters.ftplib.error_perm('500 Unknown command.')
        for line in listing:
            callback(line)

    client.retrlines.side_effect = retrlines
    monkeypatch.setattr(adapters.ftplib, 'FTP', Mock(return_value=client))
    with adapters.connect(dict(config(), protocol='ftp'), 'secret') as remote:
        assert list(remote.entries('/share', lambda: None)) == [
            ('/share/pub', 'dir', 0),
            ('/share/report 2026.csv', 'file', 12),
            ('/share/bin', 'skip', 0),
        ]


def test_ftp_missing_directory_reports_a_category_not_a_retry(monkeypatch):
    client = Mock()
    client.retrlines.side_effect = adapters.ftplib.error_perm('550 Failed to open directory.')
    monkeypatch.setattr(adapters.ftplib, 'FTP', Mock(return_value=client))
    with adapters.connect(dict(config(), protocol='ftp'), 'secret') as remote:
        with pytest.raises(adapters.SourceError, match='path_error'):
            list(remote.entries('/share/gone', lambda: None))


@pytest.mark.parametrize('reply,expected', [
    ('530 Login incorrect.', 'auth_error'),
    ('550 Failed to change directory.', 'path_error'),
    ('500 Unknown command.', 'protocol_error'),
])
def test_transport_failures_are_categorised_without_echoing_the_reply(reply, expected):
    assert adapters.category(adapters.ftplib.error_perm(reply)) == expected


def test_login_reply_text_never_reaches_the_error(monkeypatch):
    client = Mock()
    client.login.side_effect = adapters.ftplib.error_perm('530 Login incorrect for kali/kali.')
    monkeypatch.setattr(adapters.ftplib, 'FTP', Mock(return_value=client))
    with pytest.raises(adapters.SourceError) as failure:
        with adapters.connect(dict(config(), protocol='ftp'), 'secret'):
            pass
    assert str(failure.value) == 'auth_error'
    assert 'kali' not in str(failure.value)


def test_unresolvable_host_is_reported_as_a_dns_error():
    assert adapters.category(socket.gaierror(8, 'not known')) == 'dns_error'
    assert adapters.category(TimeoutError()) == 'timeout'


def test_sftp_pinned_key_rejects_unknown_key():
    key = Mock()
    key.asbytes.return_value = b'fixture-key'
    with pytest.raises(adapters.SourceError, match='host_key_mismatch'):
        adapters.PinnedKey('SHA256:wrong').missing_host_key(None, 'host', key)
