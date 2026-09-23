"""Third-party code is not the checked organisation's data.

Of 954 sensitive-data detections on one real host, 403 came from dependency and
VCS stores: a ``password`` parameter name in a pip wheel, an 11-digit codepoint
array in ``idnadata.py`` counted as a phone number, a Luhn-passing constant in a
minified bundle counted as a bank card. The walk now steps over those trees, and
because an exclusion is a scope decision rather than a coverage gap it is
reported separately instead of making the run look partial.
"""
from app.core.database import SessionLocal
from app.services.file_scan import service


def config(name, **overrides):
    data = dict(name=name, protocol='ftp', host='files.invalid', port=21, username='reader',
                password='never-return-this', root_path='/share', host_key_sha256='',
                enabled=True, limits={}, interval_minutes=15)
    data.update(overrides)
    return data


def test_a_source_created_without_a_list_gets_the_platform_default() -> None:
    with SessionLocal() as db:
        row = service.save(db, config('exclude-default'))
        assert 'node_modules' in service.excludes_for(row)
        assert 'site-packages' in service.excludes_for(row)
        # The stored limits stay a flat numeric map: the list is lifted out so the
        # console can keep formatting every entry as a coverage limit.
        assert 'exclude_paths' not in row.limits
        body = service.serialize(row)
        assert body['exclude_paths'] == []
        assert 'node_modules' in body['effective_exclude_paths']


def test_an_explicit_list_is_stored_and_reported() -> None:
    with SessionLocal() as db:
        row = service.save(db, config('exclude-explicit',
                                      exclude_paths=['node_modules', '/share/vendor']))
        assert row.limits['exclude_paths'] == ['node_modules', '/share/vendor']
        body = service.serialize(row)
        assert body['exclude_paths'] == ['node_modules', '/share/vendor']
        assert body['effective_exclude_paths'] == ['node_modules', '/share/vendor']


def test_normalization_refuses_anything_that_walks_upwards() -> None:
    with SessionLocal() as db:
        row = service.save(db, config('exclude-unsafe',
                                      exclude_paths=['../etc', 'a/../../b', '', 'keep', 'keep']))
        assert row.limits['exclude_paths'] == ['keep']


def test_build_output_names_are_deliberately_not_excluded_by_default() -> None:
    """These names are common in an organisation's own tree and may hold real
    configuration, so dropping them silently would trade a false positive for a
    missed one. An operator adds them per source."""
    for name in ('dist', 'build', 'bin', 'target', 'obj', 'out'):
        assert name not in service.DEFAULT_EXCLUDES


def test_a_bare_name_matches_the_directory_anywhere_in_the_tree() -> None:
    assert service.path_excluded('/srv/app/node_modules', ['node_modules'])
    assert service.path_excluded('/a/b/site-packages', ['site-packages'])
    assert not service.path_excluded('/srv/app/src', ['node_modules'])
    # An absolute entry names one subtree only, and must not match a sibling
    # whose name merely starts with it.
    assert service.path_excluded('/share/vendor', ['/share/vendor'])
    assert not service.path_excluded('/share/vendor-extra', ['/share/vendor'])
    assert not service.path_excluded('/other/vendor', ['/share/vendor'])


def test_a_queued_scan_freezes_the_effective_list_into_the_task() -> None:
    with SessionLocal() as db:
        row = service.save(db, config('exclude-queue'))
        task = service.queue(db, row)
        frozen = task.payload['config']['limits']['exclude_paths']
        assert 'node_modules' in frozen
