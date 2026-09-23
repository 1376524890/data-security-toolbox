"""风险文件: what fired, and the two source reads behind browsing and downloading.

The page's contract is that the risk points are *there* when a row is opened and
that a file body is never what the platform stores: browsing re-reads a bounded,
masked window and downloading re-reads the whole file, both only for a source the
platform can reach itself.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import Mock

from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import AssetInstance
from app.services.file_scan import adapters, service
from tests.test_data_objects import _file, _h, _hit, _post, _register_probe, _report

PHONE = "13800138000"


def _source_config(name: str) -> dict:
    return dict(name=name, protocol='ftp', host='files.invalid', port=21, username='reader',
                password='never-return-this', root_path='/share', host_key_sha256='',
                enabled=True, limits={}, interval_minutes=0)


def _scan_shared_file(monkeypatch, name: str, body: bytes) -> tuple[int, int]:
    """Scan a shared source whose only file is ``body``; return (source, instance)."""
    remote = Mock()
    remote.entries.return_value = [('/share/contact.csv', 'file', len(body))]
    remote.preview.side_effect = lambda path, limit: body[:limit]

    def download(path, target, consume):
        consume(len(body))
        target.write_bytes(body)

    remote.download.side_effect = download

    @contextmanager
    def connect(*_args, **_kwargs):
        yield remote

    monkeypatch.setattr(adapters, 'connect', connect)
    with SessionLocal() as db:
        source = service.save(db, _source_config(name))
        task = service.queue(db, source)
        db.commit()
        from app.services.file_scan import scan

        result = scan.run(db, task.id)
        assert result['assets'] == 1
        return source.id, result['asset_instance_ids'][0]


def test_risk_points_carry_the_matched_text_and_the_list_counts_them() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "risk-points-probe", ip="10.9.9.71")
        # counts is what the scan reports as the category's hit count, so the
        # stored detection and the list column must agree with it.
        asset = _file("/srv/risky/contacts.csv", sha=_h("risk-points"), counts={"phone": 3},
                      hits=[_hit("phone", count=3,
                                 matches=[{"value": PHONE, "context": f"owner,{PHONE}"}])])
        assert _post(client, probe_id, token, _report("r-risk-points", [asset])).status_code == 200

        rows = client.get("/api/v1/asset-instances",
                          params={"probe_id": probe_id, "sensitive_only": True}).json()["items"]
        assert rows and rows[0]["risk_point_count"] == 1
        assert rows[0]["risk_hit_count"] == 3

        points = client.get(f"/api/v1/asset-instances/{rows[0]['id']}/risk-points").json()
        assert points["detection_count"] == 1 and points["hit_count"] == 3
        assert points["matches_returned"] == 1
        point = points["items"][0]
        assert point["detection"]["category"] == "phone"
        assert point["evidence"][0]["rule_id"] == "SD_PHONE_001"
        # 直接看到风险点: the原文 the collector returned, with its line.
        assert point["evidence"][0]["matches"][0]["value"] == PHONE
        assert PHONE in point["evidence"][0]["matches"][0]["context"]


def test_a_probe_collected_file_says_it_cannot_be_re_read() -> None:
    """The platform holds no file body for a host file, and must say so."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "risk-points-probe-2", ip="10.9.9.72")
        asset = _file("/srv/risky/host-only.csv", sha=_h("risk-points-host"))
        assert _post(client, probe_id, token, _report("r-risk-host", [asset])).status_code == 200
        rows = client.get("/api/v1/asset-instances",
                          params={"probe_id": probe_id, "sensitive_only": True}).json()["items"]
        instance_id = rows[0]["id"]
        for path in (f"/api/v1/asset-instances/{instance_id}/content",
                     f"/api/v1/asset-instances/{instance_id}/download"):
            response = client.get(path)
            assert response.status_code == 409
            assert response.json()["detail"]["error"] == "not_retrievable"


def test_browsing_masks_the_returned_values_until_asked_for_everything(monkeypatch) -> None:
    body = f"name,phone\nops,{PHONE}\n".encode()
    source_id, instance_id = _scan_shared_file(monkeypatch, 'risk-mask-source', body)
    with TestClient(app) as client:
        masked = client.get(f"/api/v1/asset-instances/{instance_id}/content").json()
        assert masked["masked"] is True and masked["masked_values"] >= 1
        assert PHONE not in masked["text"]

        everything = client.get(f"/api/v1/asset-instances/{instance_id}/content",
                                params={"mask": False}).json()
        assert everything["masked"] is False
        assert PHONE in everything["text"]
        assert f"file-source:{source_id}" == _owner_key(instance_id)


def test_download_returns_the_whole_file(monkeypatch) -> None:
    # Comfortably larger than the 64 KiB browse window, so "the whole file"
    # is a claim the test can actually tell apart from a preview.
    body = ("name,phone\nops," + PHONE + "\n" + "x,y\n" * 20000).encode()
    assert len(body) > 64 * 1024
    _source_id, instance_id = _scan_shared_file(monkeypatch, 'risk-download-source', body)
    with TestClient(app) as client:
        anon = client.get(f"/api/v1/asset-instances/{instance_id}/content").json()
        assert anon["truncated"] is True

        response = client.get(f"/api/v1/asset-instances/{instance_id}/download")
        assert response.status_code == 200
        assert response.content == body
        assert response.headers["cache-control"] == "no-store"
        assert "attachment" in response.headers["content-disposition"]


def _owner_key(instance_id: int) -> str:
    with SessionLocal() as db:
        return db.get(AssetInstance, instance_id).owner_key
