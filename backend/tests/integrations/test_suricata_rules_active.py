from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete

from app.core.database import SessionLocal
from app.integrations.offline_manager import resolve_active_suricata_rules_dir, validate_suricata_rules
from app.models import OfflineResource

VALID_RULE = 'alert http any any -> any any (msg:"DST-E2E-TEST-2026"; content:"DST-E2E-TEST-2026"; sid:1000001; rev:1;)\n'


def _cleanup() -> None:
    with SessionLocal() as db:
        db.execute(delete(OfflineResource).where(OfflineResource.resource_type == "suricata_rules"))
        db.commit()


def test_validate_valid_rule(tmp_path: Path) -> None:
    rule_file = tmp_path / "valid.rules"
    rule_file.write_text(VALID_RULE)
    valid, errors = validate_suricata_rules(rule_file)
    assert valid is True
    assert errors == []


def test_validate_invalid_rule(tmp_path: Path) -> None:
    rule_file = tmp_path / "invalid.rules"
    rule_file.write_text("this is not a suricata rule at all\n")
    valid, errors = validate_suricata_rules(rule_file)
    assert valid is False
    assert errors


def test_resolve_active_rules_dir(tmp_path: Path) -> None:
    _cleanup()
    target = tmp_path / "suricata_rules"
    target.mkdir(parents=True, exist_ok=True)
    (target / "e2e.rules").write_text(VALID_RULE)
    with SessionLocal() as db:
        db.add(OfflineResource(
            resource_type="suricata_rules",
            name="e2e",
            version="1.0",
            count=1,
            status="imported",
            storage_path=str(target / "e2e.rules"),
            resource_metadata={"rule_count": 1},
        ))
        db.commit()
    # With a DB row present but no managed dir configured, resolution falls back
    # to the stored path parent.
    resolved = resolve_active_suricata_rules_dir(SessionLocal())
    assert resolved is not None
    assert Path(resolved).is_dir()
    _cleanup()
