"""The file scan and the network stage must enforce the same rules.

A fingerprint accepted from a file scan is stored on a policy group; the passive
network stage used to read only the DLP policy's own fingerprint list, so the
hash an operator had just accepted was enforced on files and ignored in traffic.
"""
import hashlib

from app.core.database import SessionLocal
from app.models import PolicyGroup
from app.services.dlp import inspect_content, normalize_policy
from app.services.policy_groups import merge_network_rules, network_rule_overlay

ACCEPTED = 'e' * 64


def _group(db, *, name: str, scope: list[str], fingerprints: list[str] | None = None,
           keywords: list[str] | None = None, enabled: bool = True) -> int:
    group = PolicyGroup(name=name, description='', enabled=enabled, scope=scope,
                        rule_ids=[], categories=[], keywords=keywords or [],
                        fingerprints=fingerprints or [], created_by='tester')
    db.add(group)
    db.commit()
    db.refresh(group)
    return group.id


def test_only_enabled_network_scoped_groups_overlay_the_network_rules():
    with SessionLocal() as db:
        _group(db, name='net-fp', scope=['file', 'network'], fingerprints=[ACCEPTED],
               keywords=['内部编号'])
        _group(db, name='file-only', scope=['file'], fingerprints=['f' * 64])
        _group(db, name='disabled-net', scope=['network'], fingerprints=['1' * 64], enabled=False)
        overlay = network_rule_overlay(db)
    assert overlay['fingerprints'] == [ACCEPTED]
    assert overlay['keywords'] == ['内部编号']


def test_merge_keeps_the_policy_own_rules_and_deduplicates():
    policy = normalize_policy({'fingerprints': [ACCEPTED], 'keywords': ['内部编号'],
                               'categories': ['email'], 'min_matches': 1})
    merged = merge_network_rules(policy, {'fingerprints': [ACCEPTED, 'a' * 64],
                                          'keywords': ['内部编号', '合同'],
                                          'categories': ['id_card']})
    assert merged['fingerprints'].count(ACCEPTED) == 1
    assert 'a' * 64 in merged['fingerprints']
    assert merged['keywords'] == ['内部编号', '合同']
    assert merged['categories'] == ['email', 'id_card']
    assert merged['min_matches'] == 1


def test_accepted_file_fingerprint_is_matched_in_network_content():
    body = b'CONFIDENTIAL-PAYROLL-2026'
    digest = hashlib.sha256(body).hexdigest()
    policy = normalize_policy(merge_network_rules(
        {'min_matches': 1, 'categories': ['email']},
        {'fingerprints': [digest], 'keywords': [], 'categories': []},
    ))
    hits = inspect_content(body, policy)
    assert any(hit['kind'] == 'file_fingerprint' and hit['samples'] == [digest] for hit in hits)
