"""Re-deriving what is already stored, and dropping findings that cannot hold.

Fixing a rule stops the *next* false positive; it does nothing about the ones
already in the database, and an operator who has just been shown 331 Swedish
organisation numbers in shell-history timestamps needs those rows gone.

Everything here works from what a row itself recorded - its rule id, its matched
values, the path it was collected from, the addresses in its evidence - and
answers one question: "would the current rule set still produce this?" A row is
removed only when its own evidence says no. Nothing is re-scanned, nothing is
inferred from a pattern that the row does not carry, and every removal is
reported per reason and written to the audit log by the caller.

Deliberately *not* a blanket "delete everything that looks wrong": a rule an
analyst deleted, a path that moved, or a host that went away must not silently
erase history, so none of those count as evidence of a false positive.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Alert,
    AssetInstance,
    Detection,
    DetectionEvidence,
    DetectionFinding,
)
from app.services import sensitive_engine

#: Reasons a stored row can be shown to be stale, in the order they are tested.
REASON_VALIDATOR = "validator_rejects_stored_value"
REASON_CONFIDENCE = "rule_below_alert_confidence"
REASON_EXCLUDED_PATH = "path_excluded_by_scope"
REASON_IGNORED_ADDRESS = "evidence_address_out_of_scope"

_IP_KEYS = ("src", "dst", "src_ip", "dst_ip", "source_ip", "target_ip", "peer_ip")
#: Evidence keys that name the file a finding was raised from. Only keys that are
#: a real path count: ``source`` is usually a bare file name, so matching a root
#: against it would delete findings from anywhere on the host.
_FILE_KEYS = ("file", "path")


def _values(evidence: DetectionEvidence) -> list[str]:
    """Matched values a piece of evidence recorded, bounded like the engine."""
    extra = evidence.extra or {}
    matches = extra.get("matches")
    if not isinstance(matches, list):
        return []
    values = []
    for item in matches:
        if isinstance(item, dict):
            value = item.get("value")
        else:
            value = item
        if value:
            values.append(str(value))
    return values


def _current_rules() -> dict[str, dict[str, Any]]:
    """Every rule the platform scans with right now, by rule id."""
    return {str(rule.get("rule_id")): rule for rule in sensitive_engine.scan_engine().rules}


def _addresses(evidence: dict[str, Any] | None) -> list[str]:
    found: list[str] = []
    payload = evidence or {}
    for key in _IP_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            found.append(value)
    for key in ("src_dst", "endpoints"):
        value = payload.get(key)
        if isinstance(value, list):
            found.extend(str(item) for item in value if item)
    return found


def _networks(entries: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    parsed = []
    for entry in entries or []:
        text = str(entry).strip()
        if not text:
            continue
        try:
            parsed.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return parsed


def _address_matches(value: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in networks)


def _excluded_path(path: str, excludes: list[str]) -> bool:
    for entry in excludes:
        if entry.startswith("/"):
            if path == entry or path.startswith(entry + "/"):
                return True
        elif entry and entry in path.split("/"):
            return True
    return False


def _excluded_paths(db: Session) -> list[str]:
    """The union of every file source's effective exclusion list."""
    from app.models import FileSource
    from app.services.file_scan import service as file_scan_service

    entries: list[str] = []
    for row in db.scalars(select(FileSource)).all():
        for entry in file_scan_service.excludes_for(row):
            if entry not in entries:
                entries.append(entry)
    return entries


def stale_file_detections(
    db: Session,
    *,
    revalidate: bool = True,
    excluded_paths: bool = True,
) -> dict[str, Any]:
    """Detections the current rules and scope would no longer produce.

    Returns the rows to remove, grouped by reason, without touching the session.
    """
    rules = _current_rules() if revalidate else {}
    excludes = _excluded_paths(db) if excluded_paths else []
    victims: dict[str, list[Detection]] = {
        REASON_VALIDATOR: [],
        REASON_CONFIDENCE: [],
        REASON_EXCLUDED_PATH: [],
    }
    instances = {
        row.id: row.path for row in db.scalars(select(AssetInstance)).all()
    }
    rows = db.scalars(select(Detection)).all()
    evidence_by_detection: dict[int, list[DetectionEvidence]] = {}
    for item in db.scalars(select(DetectionEvidence)).all():
        evidence_by_detection.setdefault(item.detection_id, []).append(item)
    for detection in rows:
        if excluded_paths:
            path = instances.get(detection.instance_id, "")
            if path and _excluded_path(path, excludes):
                victims[REASON_EXCLUDED_PATH].append(detection)
                continue
        if not revalidate:
            continue
        items = evidence_by_detection.get(detection.id, [])
        if not items:
            continue
        reasons = []
        # Which check said no matters to the operator: "the value no longer
        # passes its validator" is a different answer from "the rule can no
        # longer confirm", and the two are fixed by different actions.
        rejected_by_validator = False
        for evidence in items:
            rule = rules.get(str(evidence.rule_id))
            if rule is None:
                # A rule the operator removed is not proof its hits were wrong.
                reasons.append(False)
                continue
            values = _values(evidence)
            validator = str(rule.get("validator") or "")
            if validator:
                check = _validator(validator)
                if check is not None and values:
                    accepted = any(check(value).accepted for value in values)
                    rejected_by_validator = rejected_by_validator or not accepted
                    reasons.append(accepted)
                    continue
            # No validator: the rule's own current confidence decides.
            reasons.append(float(rule.get("confidence") or 0) >= _confirm_threshold())
        if reasons and not any(reasons):
            victims[REASON_VALIDATOR if rejected_by_validator else REASON_CONFIDENCE].append(
                detection
            )
    return {
        "reasons": {key: [row.id for row in value] for key, value in victims.items()},
        "counts": {key: len(value) for key, value in victims.items()},
        "total": sum(len(value) for value in victims.values()),
        "rows": victims,
    }


def _validator(name: str):
    """The value-level check a rule names, or ``None`` if the platform lost it."""
    from shared.sensitive_detection.validators import get_validator

    return get_validator(name)


def _confirm_threshold() -> float:
    from shared.sensitive_detection.confidence import CONFIRMED_CONFIDENCE

    return CONFIRMED_CONFIDENCE


def stale_traffic_findings(db: Session, addresses: Iterable[str]) -> list[DetectionFinding]:
    """Findings whose evidence sits on an address the operator ruled out.

    Used for the capture-scope mistakes - a probe that recorded the platform's own
    container bridge, or loopback traffic - where the addresses are the proof and
    the operator names the range. An empty list matches nothing: a purge must
    never be the default.
    """
    networks = _networks(addresses)
    if not networks:
        return []
    victims: list[DetectionFinding] = []
    for finding in db.scalars(select(DetectionFinding)).all():
        found = _addresses(finding.evidence)
        if found and any(_address_matches(value, networks) for value in found):
            victims.append(finding)
    return victims


def _file_roots(entries: Iterable[str]) -> list[str]:
    roots = []
    for entry in entries or ():
        text = str(entry).strip().rstrip("/")
        if text and text.startswith("/") and ".." not in text.split("/"):
            roots.append(text)
    return roots


def _under(path: str, roots: list[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def stale_file_findings(db: Session, roots: Iterable[str]) -> list[DetectionFinding]:
    """Findings raised *from* a file the operator has named out of scope.

    The platform's own storage holds the captures and reports it produced, so a
    finding that names a file inside it describes the checker rather than the
    customer -- the same reasoning as the address range, and just as explicit: an
    empty list matches nothing.
    """
    named = _file_roots(roots)
    if not named:
        return []
    victims: list[DetectionFinding] = []
    for finding in db.scalars(select(DetectionFinding)).all():
        evidence = finding.evidence or {}
        found = [
            str(evidence[key]) for key in _FILE_KEYS
            if isinstance(evidence.get(key), str) and evidence.get(key)
        ]
        if any(_under(path, named) for path in found):
            victims.append(finding)
    return victims


def stale_rule_findings(db: Session, rules: Iterable[str]) -> list[DetectionFinding]:
    """Findings from a rule the operator has verified is stale.

    A rule that described the metric wrongly (a server's directional replies
    read as a port scan, a whole-segment byte count read as a host's traffic)
    keeps its findings after the rule is corrected: the fix stops the next one,
    not the ones already stored. Naming the rule id is the operator's explicit
    statement that the history it produced cannot hold - an empty list matches
    nothing, exactly like the address and root sweeps.
    """
    named = sorted({str(entry).strip() for entry in rules or () if str(entry).strip()})
    if not named:
        return []
    query = select(DetectionFinding).where(DetectionFinding.rule_id.in_(named))
    return list(db.scalars(query).all())


def purge(
    db: Session,
    *,
    revalidate: bool = True,
    exclude_owned_paths: bool = True,
    addresses: Iterable[str] = (),
    roots: Iterable[str] = (),
    rules: Iterable[str] = (),
    dry_run: bool = True,
) -> dict[str, Any]:
    """Apply the verdicts above. ``dry_run`` reports without deleting.

    Deleting a finding has to take its dependants with it: ``alert_hits``
    cascades, but ``alerts.finding_id`` does not, and an alert whose finding was
    proven stale is the alert the operator asked to be rid of. Incidents are not
    touched - they are derived by the correlation engine and are rebuilt from the
    surviving findings with ``POST /incidents/rebuild-attribution``. ``addresses``,
    ``roots`` and ``rules`` are the operator-named out-of-scope inputs described
    above; each is empty by default so a purge never happens by accident.
    """
    verdict = stale_file_detections(db, revalidate=revalidate, excluded_paths=exclude_owned_paths)
    findings = (stale_traffic_findings(db, addresses) + stale_file_findings(db, roots)
                + stale_rule_findings(db, rules))
    evidence_rows = 0
    alert_rows = 0
    if not dry_run:
        for rows in verdict["rows"].values():
            for detection in rows:
                evidence_rows += db.query(DetectionEvidence).filter(
                    DetectionEvidence.detection_id == detection.id
                ).delete(synchronize_session=False)
                db.delete(detection)
        for finding in findings:
            alert_rows += db.query(Alert).filter(Alert.finding_id == finding.id).delete(
                synchronize_session=False
            )
            db.delete(finding)
        db.flush()
    summary = {
        "dry_run": bool(dry_run),
        "detections": verdict["counts"],
        "detections_total": verdict["total"],
        "detection_evidence_deleted": evidence_rows,
        "findings": len(findings),
        "alerts_deleted": alert_rows,
        "addresses": [str(item) for item in addresses],
        "roots": _file_roots(roots),
        "rules": sorted({str(item).strip() for item in rules or () if str(item).strip()}),
    }
    if dry_run:
        summary["sample_detection_ids"] = {
            key: ids[:20] for key, ids in verdict["reasons"].items() if ids
        }
        summary["sample_finding_ids"] = [row.id for row in findings[:20]]
    return summary
