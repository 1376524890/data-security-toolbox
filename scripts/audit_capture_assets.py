"""Read-only audit of legacy capture-container data-asset projections.

Run in the backend environment: python scripts/audit_capture_assets.py
No rows or files are changed. Matching is intentionally stricter than a suffix.
"""
import json
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.core.database import SessionLocal
from app.models import DataAsset, PcapRecord
from sqlalchemy import select


def audit(db):
    captures = {}
    for capture in db.scalars(select(PcapRecord)):
        name = PurePosixPath(capture.storage_path).name
        if name:
            captures.setdefault(name, []).append(capture.id)
    candidates = []
    for asset in db.scalars(select(DataAsset)):
        # Real inventory/uploaded files carry provenance; never classify those
        # by extension alone. Ambiguous matches remain for manual investigation.
        ids = captures.get(asset.name, [])
        if (len(ids) == 1 and asset.source == asset.name and asset.asset_type == 'file'
                and asset.sensitivity == 'Unknown' and not asset.columns and not asset.extra):
            candidates.append({'data_asset_id': asset.id, 'pcap_id': ids[0], 'name': asset.name})
    return {'mode': 'read-only', 'candidate_count': len(candidates), 'candidates': candidates,
            'note': 'Candidates only; verify analysis history before any archived repair.'}


if __name__ == '__main__':
    with SessionLocal() as session:
        print(json.dumps(audit(session), ensure_ascii=False, indent=2))
