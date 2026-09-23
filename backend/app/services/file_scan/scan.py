"""Bounded enumeration, temporary downloads, detection and progress."""
import hashlib
import shutil
import tempfile
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

#: Every download of one scan lives under ``<tmp>/dst-file-scan-*``. Named so a
#: crashed run can be told apart from anything else in the system temporary dir.
TEMP_PREFIX = 'dst-file-scan-'

#: A scan writes one whole file at a time and unlinks it immediately, so an
#: orphan older than this cannot belong to a live run - only to a worker that was
#: killed between the download and its cleanup.
STALE_TEMP_AGE_SECONDS = 6 * 3600


def _is_global_stop(exc: BaseException) -> bool:
    return isinstance(exc, adapters.SourceError) and str(exc) in GLOBAL_STOPS


def sweep_stale_temp_dirs(max_age_seconds: float = STALE_TEMP_AGE_SECONDS) -> int:
    """Delete scan temp dirs a killed worker left behind; return how many went.

    While the process lives, the per-file ``unlink`` and the surrounding
    ``TemporaryDirectory`` are enough. Neither can run when the worker is
    ``SIGKILL``ed or the container is stopped mid-download, and the leftovers
    hold whole *copied files* - a multi-gigabyte dump on a share would then sit
    in ``/tmp`` for good. The age guard is what keeps this from racing a live
    scan in another worker: anything still being written is far younger.
    """
    root = Path(tempfile.gettempdir())
    cutoff = time.time() - max_age_seconds
    removed = 0
    for entry in root.glob(f'{TEMP_PREFIX}*'):
        try:
            if entry.stat().st_mtime >= cutoff:
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
        except OSError:
            # A temp dir we cannot inspect is not worth failing a worker start
            # over; the next start tries again.
            continue
        removed += 1
    return removed


def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    """Whole-file SHA256 read in chunks, so size never becomes a memory cost."""
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(chunk), b''):
            digest.update(block)
    return digest.hexdigest()


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
    #: Files that were listed and stored, but whose *content* was only sampled or
    #: not decoded at all (binaries). Sampling is a detection strategy, not a hole
    #: in the walk, so it is reported separately instead of making the whole scope
    #: "Partial" - which is what used to happen and left an operator unable to tell
    #: a finished inventory from an aborted one.
    sampled: list[dict[str, str]] = []
    metadata_only = 0
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
                with TemporaryDirectory(prefix=TEMP_PREFIX) as temp:
                    while queue:
                        check()
                        directory, depth = queue.pop()
                        dirs += 1
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
                                # A directory that could not be listed means the
                                # scope was not covered. Leaving ``complete`` true
                                # here is how a scan of a root that does not exist
                                # reported "Success / 0 files" and would have let
                                # the platform retire every asset it had seen.
                                complete, reason = False, 'unreadable'
                                continue
                        for path, kind, size in entries:
                            check()
                            if kind == 'dir':
                                # 0 = walk the whole tree; an explicit depth is the
                                # operator's own cap and is reported when it bites.
                                if not limits['max_depth'] or depth < limits['max_depth']:
                                    queue.append((path, depth + 1))
                                else:
                                    complete, reason = False, 'depth_limit'
                                continue
                            if kind != 'file':
                                skipped += 1
                                continue
                            # 0 = no file cap; the walk is bounded by the scope itself.
                            if limits['max_files'] and len(ids) >= limits['max_files']:
                                raise adapters.SourceError('file_budget')
                            seen.add(path)
                            scan = {'counts': {}, 'hits': [], 'rows': 0,
                                    'coverage': 'partial', 'reason': 'single_file_limit'}
                            if limits['max_file_bytes'] and size > limits['max_file_bytes']:
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
                                    file_cap = limits['max_file_bytes']
                                    byte_cap = limits['max_bytes']
                                    if file_cap and file_bytes > file_cap:
                                        raise adapters.SourceError('single_file_limit')
                                    if byte_cap and total_bytes > byte_cap:
                                        raise adapters.SourceError('byte_budget')
                                try:
                                    remote.download(path, local, consume)
                                    scan = ingest.analyze(local, limits)
                                    # Streamed, not read into memory: with no file-size cap, a large
                                    # dump would otherwise be loaded whole just to be hashed.
                                    scan['hash'] = _sha256_file(local)
                                    if file_bytes != size:
                                        scan.update(coverage='partial', reason='file_changed_during_read')
                                    if scan['coverage'] == 'unsupported':
                                        # Binary content is not decoded by design; the
                                        # file is still inventoried in full.
                                        metadata_only += 1
                                    elif scan['coverage'] != 'complete':
                                        reason = str(scan.get('reason') or 'sampled')
                                        sampled.append({'path': path, 'reason': reason})
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
                            # With no file cap there is no honest denominator, so the
                            # bar advances on a log-shaped curve instead of dividing by 0.
                            cap = limits['max_files']
                            task.progress = (min(95, int(len(ids) / cap * 95)) if cap
                                             else min(95, 5 + len(ids) * 90 // (len(ids) + 200)))
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
                   # Never cut the list: an operator chasing a coverage gap needs
                   # every path that was not read, not the first 200.
                   'unreadable': unreadable, 'unreadable_count': len(unreadable),
                   # Each of these is a separate, named answer: the tree was walked
                   # in full (enumeration), only some file *contents* were sampled,
                   # and some files were inventoried without decoding.
                   'enumeration_complete': complete,
                   'content_complete': not sampled,
                   'sampled': sampled, 'sampled_count': len(sampled),
                   'metadata_only': metadata_only,
                   'source_id': source.id, 'source_name': source.name, 'operation': task.payload.get('operation')}
    source.last_status = status
    if unreadable and not task.error:
        task.error = f'{len(unreadable)} 个目录/文件未能读取（{reason}）'
    source.last_error = task.error
    if task.payload.get('operation') != 'test':
        source.last_scan_at = task.finished_at
    db.commit()
    return task.result
