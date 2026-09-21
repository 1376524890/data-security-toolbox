"""Bounded enumeration, temporary downloads, detection and progress."""
import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from sqlalchemy import select
from app.models import AssetInstance, DataObject, FileSource, Task
from app.services.data_objects.persistence import recount_object
from . import adapters, ingest, service

#: Stops that mean "this scan is over", not "this one item is unreadable". They
#: are raised from ``check()`` deep inside the loops, so the per-item handlers
#: must let them through instead of recording them as unreadable content.
GLOBAL_STOPS = frozenset({'time_budget', 'cancelled', 'byte_budget'})


def _is_global_stop(exc: BaseException) -> bool:
    return isinstance(exc, adapters.SourceError) and str(exc) in GLOBAL_STOPS


def run(db, task_id):
    task = db.scalar(select(Task).where(Task.id == task_id).with_for_update())
    if task is None or task.status != 'Pending':
        return
    source = db.get(FileSource, task.payload['source_id'])
    task.status = 'Running'
    task.started_at = datetime.now(UTC)
    task.current_stage = '连接共享文件源'
    db.commit()
    config = task.payload['config']
    limits = config['limits']
    start = time.monotonic()
    last_check = 0.0
    ids, errors, seen = [], [], set()
    # Directories and files that could not be read are listed explicitly: a scan
    # that silently dropped them would look clean while having skipped content.
    unreadable: list[dict[str, str]] = []
    total_bytes = new = changed = sensitive = skipped = dirs = 0
    complete, reason = True, 'complete'

    def check():
        nonlocal last_check
        # 0 seconds = no time limit; bytes and files still bound the run.
        if limits['max_seconds'] and time.monotonic() - start > limits['max_seconds']:
            raise adapters.SourceError('time_budget')
        if time.monotonic() - last_check > 1:
            db.refresh(task)
            last_check = time.monotonic()
            if task.status == 'Cancelled':
                raise adapters.SourceError('cancelled')

    try:
        with adapters.connect(config, service.password(source)) as remote:
            if task.payload.get('operation') == 'test':
                # Verify the selected root too, but do not download or persist assets.
                next(iter(remote.entries(config['root_path'], check)), None)
            else:
                queue = [(config['root_path'], 0)]
                with TemporaryDirectory(prefix='dst-file-scan-') as temp:
                    while queue:
                        check()
                        directory, depth = queue.pop()
                        dirs += 1
                        if dirs > 500:
                            raise adapters.SourceError('directory_budget')
                        listing_error: Exception | None = None
                        try:
                            entries = list(remote.entries(directory, check))
                        except Exception as exc:  # noqa: BLE001 - classified below
                            if _is_global_stop(exc):
                                raise
                            entries = None
                            listing_error = exc
                        if entries is None:
                            # A name that is not valid UTF-8 makes the SFTP
                            # listing itself raise. Retry once with a raw listing
                            # so one bad name does not lose the whole directory.
                            try:
                                entries = list(remote.entries_raw(directory, check))
                            except Exception as exc:  # noqa: BLE001 - one bad directory
                                if _is_global_stop(exc):
                                    raise
                                unreadable.append({'path': directory,
                                                   'reason': type(listing_error).__name__,
                                                   'fallback': type(exc).__name__})
                                skipped += 1
                                continue
                        for path, kind, size in entries:
                            check()
                            if kind == 'dir':
                                if depth < limits['max_depth']:
                                    queue.append((path, depth + 1))
                                else:
                                    complete, reason = False, 'depth_limit'
                                continue
                            if kind != 'file':
                                skipped += 1
                                continue
                            if len(ids) >= limits['max_files']:
                                raise adapters.SourceError('file_budget')
                            seen.add(path)
                            scan = {'counts': {}, 'hits': [], 'rows': 0,
                                    'coverage': 'partial', 'reason': 'single_file_limit'}
                            if size > limits['max_file_bytes']:
                                skipped += 1
                                complete, reason = False, 'single_file_limit'
                            else:
                                local = Path(temp) / ('content' + Path(path).suffix[:16])
                                file_bytes = 0
                                def consume(count):
                                    nonlocal total_bytes, file_bytes
                                    check()
                                    file_bytes += count
                                    total_bytes += count
                                    if file_bytes > limits['max_file_bytes']:
                                        raise adapters.SourceError('single_file_limit')
                                    if total_bytes > limits['max_bytes']:
                                        raise adapters.SourceError('byte_budget')
                                try:
                                    remote.download(path, local, consume)
                                    scan = ingest.analyze(local)
                                    scan['hash'] = hashlib.sha256(local.read_bytes()).hexdigest()
                                    if file_bytes != size:
                                        scan.update(coverage='partial', reason='file_changed_during_read')
                                    if scan['coverage'] != 'complete':
                                        complete, reason = False, scan['reason']
                                except Exception as exc:  # noqa: BLE001 - one bad file
                                    if _is_global_stop(exc):
                                        raise
                                    # A file we could not read is recorded as failed
                                    # rather than dropped: an unreadable asset must
                                    # never look like a clean one.
                                    scan = {'counts': {}, 'hits': [], 'rows': 0,
                                            'coverage': 'failed',
                                            'reason': type(exc).__name__}
                                    unreadable.append({'path': path,
                                                       'reason': type(exc).__name__})
                                    complete, reason = False, type(exc).__name__
                                finally:
                                    local.unlink(missing_ok=True)
                            instance, added, modified = ingest.store(db, source, task, path, size,
                                                                    scan, datetime.now(UTC))
                            ids.append(instance.id)
                            new += int(added)
                            changed += int(modified)
                            sensitive += bool(scan['counts'])
                            task.result = {'assets': len(ids), 'asset_instance_ids': list(ids),
                                           'new': new, 'changed': changed, 'sensitive': sensitive}
                            task.current_stage = f'已采集 {len(ids)} 个文件'
                            task.progress = min(95, int(len(ids) / limits['max_files'] * 95))
                            db.commit()
    except Exception as exc:
        complete = False
        reason = str(exc) if isinstance(exc, adapters.SourceError) else type(exc).__name__
        errors.append(reason)
        db.rollback()
        task = db.get(Task, task_id)
        source = db.get(FileSource, task.payload['source_id'])
    db.refresh(task)
    if task.status == 'Cancelled':
        complete, reason = False, 'cancelled'
    retired = 0
    if complete and task.payload.get('operation') != 'test':
        for item in db.scalars(select(AssetInstance).where(
                AssetInstance.owner_key == f'file-source:{source.id}', AssetInstance.status == 'ACTIVE')):
            if item.path not in seen:
                item.status = 'NOT_OBSERVED'
                retired += 1
                db.flush()
                recount_object(db, db.get(DataObject, item.object_id))
    status = ('Cancelled' if reason == 'cancelled' else 'Success' if complete
              else 'Partial' if ids else 'Failed')
    task.status, task.progress, task.finished_at = status, 100, datetime.now(UTC)
    task.current_stage = '连接检查完成' if task.payload.get('operation') == 'test' and complete else reason
    task.error = '; '.join(errors)
    task.result = {'assets': len(ids), 'asset_instance_ids': ids, 'new': new, 'changed': changed,
                   'sensitive': sensitive, 'not_observed': retired, 'skipped': skipped,
                   'bytes_read': total_bytes, 'complete_scope': complete, 'termination_reason': reason,
                   # Named explicitly so a partial scan can never read as a clean
                   # one: these are the directories/files that were not read.
                   'unreadable': unreadable[:200], 'unreadable_count': len(unreadable),
                   'source_id': source.id, 'source_name': source.name, 'operation': task.payload.get('operation')}
    source.last_status = status
    if unreadable and not task.error:
        task.error = f'{len(unreadable)} 个目录/文件未能读取（{reason}）'
    source.last_error = task.error
    if task.payload.get('operation') != 'test':
        source.last_scan_at = task.finished_at
    db.commit()
    return task.result
