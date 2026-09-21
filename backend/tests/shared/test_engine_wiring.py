"""Proof that the probe, the platform and NetDLP run one engine, not four.

Stage 1's completion criterion is that the file scan and the network DLP stage
really call the shared code rather than a new class nobody uses, so these tests
check the wiring and the HTTP boundary instead of the engine's arithmetic.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services import sensitive_engine
from shared.scanning.budget import ScanBudget

REPO_ROOT = Path(__file__).resolve().parents[3]

# Patterns that used to exist as three divergent copies (probe, data engine and
# the DLP service). Only the shared pack may define detection rules now.
DETECTION_PATTERN_FRAGMENTS = ("1[3-9]\\d{9}", "(?:18|19|20)")
SHARED_ONLY_DIRS = (REPO_ROOT / "backend" / "app", REPO_ROOT / "probe")

PHONE = "13800138000"
ID_CARD = "110101199003071234"


def test_detection_patterns_are_defined_only_in_the_shared_pack() -> None:
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for directory in SHARED_ONLY_DIRS
        for path in sorted(directory.rglob("*.py"))
        if any(fragment in path.read_text(encoding="utf-8") for fragment in DETECTION_PATTERN_FRAGMENTS)
    ]
    assert offenders == []


def test_probe_and_platform_resolve_the_same_rule_pack() -> None:
    from shared.sensitive_detection import build_engine

    from probe import data_assets

    shared_ids = [rule["rule_id"] for rule in build_engine().rules]
    assert shared_ids
    assert [rule["rule_id"] for rule in sensitive_engine.get_engine().rules] == shared_ids
    assert [rule["rule_id"] for rule in data_assets.engine().rules] == shared_ids
    assert data_assets.engine().capabilities()["engine_version"] == \
        sensitive_engine.engine_metadata()["engine_version"]
    assert sensitive_engine.SHARED_ROOT is not None


def test_probe_file_scan_reports_shared_entities_and_the_matched_text(tmp_path: Path) -> None:
    from probe import data_assets

    sample = tmp_path / "customers.csv"
    sample.write_text(f"name,phone,id_card\n张三,{PHONE},{ID_CARD}\n", encoding="utf-8")
    record = data_assets.inspect_file(sample, ScanBudget())
    assert record is not None
    assert {"phone", "id_card"} <= set(record["categories"])
    hits = {item["entity"]: item for item in record["evidence"]["hits"]}
    assert {"PHONE", "ID_CARD"} <= set(hits)
    # Evidence explains a hit through rules and levels; the value travels beside
    # it in ``matches`` (operator requirement: a finding must be verifiable).
    assert hits["PHONE"]["rule_ids"] and hits["PHONE"]["severity"] == "Medium"
    assert hits["PHONE"]["matches"][0]["value"] == PHONE
    assert hits["ID_CARD"]["matches"][0]["value"] == ID_CARD
    blob = json.dumps(record, ensure_ascii=False)
    for hit in hits.values():
        for match in hit["matches"]:
            assert len(match["value"]) <= 120 and len(match["context"]) <= 240
    # A column is scanned from its own sampled cells, so the returned context is
    # the line that value sits on and never the surrounding row. The report still
    # holds no sample-value list: what travels is the matched原文, not the file.
    assert hits["PHONE"]["matches"][0]["context"] == PHONE
    assert hits["ID_CARD"]["matches"][0]["context"] == ID_CARD
    assert "values" not in blob


def test_probe_report_guard_produces_a_payload_the_platform_accepts(tmp_path: Path) -> None:
    from shared.sensitive_detection.report_guard import sanitize_report, validate_report

    from probe import data_assets

    sample = tmp_path / "customers.csv"
    sample.write_text(f"phone\n{PHONE}\n", encoding="utf-8")
    report = data_assets.discover_data_assets(
        {"paths": [str(tmp_path)], "max_files": 10, "max_depth": 2, "include_databases": False})
    report.update(report_id="guard01", task_id=1)
    guarded = data_assets.guard_report(report)
    assert validate_report(guarded) == []
    assert guarded["report_guard"] == {"redacted": 0, "truncated": 0, "dropped_keys": 0}
    # A path that itself carries a value is redacted and the redaction is counted.
    clean, audit = sanitize_report({"assets": [{"path": f"/srv/{PHONE}.csv"}]})
    assert clean["assets"][0]["path"] == "[redacted]"
    assert audit.to_dict()["redacted"] == 1


def test_netdlp_text_stage_uses_the_shared_engine() -> None:
    from app.services.dlp import inspect_content

    policy = {"categories": ["phone", "id_card"], "min_matches": 1}
    hits = {item["kind"]: item for item in inspect_content(
        f"phone={PHONE}&id_card={ID_CARD}".encode(), policy)}
    assert {"phone", "id_card"} <= set(hits)
    assert hits["phone"]["confidence"] == 0.7
    assert hits["id_card"]["entity"] == "ID_CARD"
    assert hits["phone"]["samples"] == []
    # The matched原文 rides in ``matches`` only; that is the one key allowed to
    # carry it, and it is bounded by the shared engine the platform runs.
    assert hits["phone"]["matches"] == [{"value": PHONE, "context": f"phone={PHONE}&id_card={ID_CARD}"}]
    without_matches = {key: value for key, value in hits["phone"].items() if key != "matches"}
    assert PHONE not in json.dumps(without_matches, ensure_ascii=False)


def test_policy_keyword_hits_carry_the_matched_line() -> None:
    from app.services.dlp import inspect_content

    hits = {item["kind"]: item for item in inspect_content(
        "内部机密：项目A".encode(), {"categories": [], "keywords": ["内部机密"], "min_matches": 1})}
    assert hits["keyword"]["rule_source"] == "policy_keyword"
    assert hits["keyword"]["matches"] == [{"value": "内部机密", "context": "内部机密：项目A"}]


def _http_capture(path: Path, body: bytes) -> Path:
    """One cleartext HTTP POST, the shape the passive DLP stage reassembles."""
    import socket

    import dpkt

    payload = (b"POST /upload HTTP/1.1\r\nHost: bi.example.com\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
    tcp = dpkt.tcp.TCP(sport=51000, dport=80, seq=1, flags=dpkt.tcp.TH_ACK, data=payload)
    packet = dpkt.ip.IP(src=socket.inet_aton("10.0.0.12"), dst=socket.inet_aton("10.0.0.33"),
                        p=6, data=tcp)
    packet.len = len(packet)
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle, linktype=101)
        writer.writepkt(bytes(packet), ts=1)
    return path


def test_a_console_rule_is_one_rule_for_files_and_for_the_network(tmp_path: Path, monkeypatch) -> None:
    """The requirement: a rule added in the console matches everywhere, with原文.

    One rule store feeds the file scan (敏感发现), the network DLP text stage
    (网络防泄密) and, through the finding it raises, the realtime alert stream.
    """
    from app.core.config import settings
    from app.engine.data_engine.engine import scan_text
    from app.services import rule_library
    from app.services.dlp import analyze_capture

    monkeypatch.setattr(settings, "integration_dir", tmp_path / "integrations")
    rule_library.save_manual_rule({"name": "规则测试", "entity": "测试", "pattern": "张三", "confidence": 0.7})

    scan = scan_text(f"客户姓名：张三，联系方式 {PHONE}")
    custom = {hit["entity"]: hit for hit in scan["confirmed_hits"]}["测试"]
    assert scan["counts"]["测试"] == 1
    assert custom["matches"] == [{"value": "张三", "context": f"客户姓名：张三，联系方式 {PHONE}"}]

    path = _http_capture(tmp_path / "name.pcap", "姓名=张三&phone=13800138000".encode())
    result, _, findings = analyze_capture(path, {"categories": ["phone"], "min_matches": 1})
    hits = {hit["kind"]: hit for hit in result["objects"][0]["matches"]}
    assert hits["测试"]["matches"][0]["value"] == "张三"
    # The finding behind the realtime alert carries the same原文.
    raised = {hit["kind"]: hit for hit in findings[0]["evidence"]["matches"]}
    assert raised["测试"]["matches"][0]["value"] == "张三"
    assert "测试" in findings[0]["evidence"]["triggered_by"]


def test_a_rule_added_later_is_picked_up_without_a_restart(tmp_path: Path, monkeypatch) -> None:
    from app.core.config import settings
    from app.services import rule_library

    monkeypatch.setattr(settings, "integration_dir", tmp_path / "integrations")
    assert sensitive_engine.scan_all("张三") == []
    stored = rule_library.save_manual_rule({"name": "规则测试", "entity": "测试", "pattern": "张三"})
    hits = {hit.entity: hit for hit in sensitive_engine.scan_all("张三")}
    assert hits["测试"].rule_ids == [stored["id"]]


def test_presidio_static_hits_are_never_labelled_as_a_runtime_run() -> None:
    from app.integrations.presidio.recognizers import presidio_scan, presidio_status

    records = presidio_scan(f"身份证 {ID_CARD}")
    status = presidio_status()
    assert status["reason"] or status["available"]
    sources = {item["rule_source"] for item in records}
    if status["available"] and status["enabled"]:
        assert sources == {"presidio_runtime"}
    else:
        # No NLP model installed: the static pack answers and says so.
        assert sources == {"presidio_static"}
        assert status["reason"]
    assert ID_CARD not in json.dumps(records)


def test_presidio_adapter_evidence_carries_no_sample_values() -> None:
    from app.integrations.presidio.adapter import PresidioAdapter

    result = PresidioAdapter().adapt({"text": f"身份证号 {ID_CARD} 手机号 {PHONE}"})
    assert result.findings
    blob = json.dumps([dict(item.evidence) for item in result.findings], ensure_ascii=False, default=str)
    assert ID_CARD not in blob and PHONE not in blob
    for item in result.findings:
        assert "sample" not in " ".join(item.evidence)


def _register(client: TestClient, name: str) -> tuple[int, str]:
    response = client.post("/api/v1/probes/register",
                           json={"name": name, "hostname": name, "ip_address": "10.9.9.7", "metadata": {}})
    assert response.status_code == 200
    body = response.json()
    return body["id"], body["token"]


def _headers(probe_id: int, token: str) -> dict[str, str]:
    return {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}


def _clean_report() -> dict:
    return {
        "report_id": "wiring0001",
        "assets": [{
            "name": "wiring-assets.csv", "asset_type": "table", "sensitivity": "High",
            "path": "/srv/wiring/customers.csv", "size": 2048, "sha256": "b" * 64,
            "modified_at": "2026-09-15T00:00:00+00:00",
            "categories": ["phone"], "counts": {"phone": 1},
            "columns": [{"name": "phone", "detected_type": "phone", "sensitivity": "Medium",
                         "confidence": 0.7, "categories": ["phone"], "count": 1}],
            "evidence": {"extension": ".csv", "hits": [{"entity": "PHONE", "count": 1}]},
        }],
        "databases": [], "scanned_paths": ["/srv/data"], "max_depth": 3,
        "complete": True, "error": "", "observed_at": "2026-09-15T00:00:00+00:00",
        "scanner": "probe-file-inventory",
        "report_guard": {"redacted": 0, "truncated": 0, "dropped_keys": 0},
    }


def test_legacy_report_shape_is_still_accepted() -> None:
    # Names are test-specific on purpose: the shared test database keeps rows from
    # other tests, and the existing ingest test queries by asset name globally.
    with TestClient(app) as client:
        probe_id, token = _register(client, "wiring-legacy")
        response = client.post(f"/api/v1/probes/{probe_id}/data-assets",
                               json=_clean_report(), headers=_headers(probe_id, token))
        assert response.status_code == 200, response.text
        assert response.json()["assets"] == 1


def test_report_smuggling_a_raw_value_is_rejected_with_codes_only() -> None:
    with TestClient(app) as client:
        probe_id, token = _register(client, "wiring-unsafe")
        payload = _clean_report()
        payload["assets"][0]["evidence"]["samples"] = [PHONE]
        response = client.post(f"/api/v1/probes/{probe_id}/data-assets",
                               json=payload, headers=_headers(probe_id, token))
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["error"] == "unsafe_report"
        assert detail["violations"] == [{"path": "$.assets[0].evidence.samples", "code": "forbidden_key"}]
        # The rejection must not echo the value it refused.
        assert PHONE not in response.text


def test_probe_authentication_bodies_are_not_run_through_the_report_guard() -> None:
    """A `token`/`password` field in auth traffic is normal, not data smuggling."""
    with TestClient(app) as client:
        response = client.post("/api/v1/probes/register", json={
            "name": "wiring-auth", "hostname": "wiring-auth", "ip_address": "10.9.9.6",
            "metadata": {"token": "not-a-real-token", "password": "not-a-real-password"}})
        assert response.status_code == 200, response.text
        probe_id, token = response.json()["id"], response.json()["token"]
        heartbeat = client.post(f"/api/v1/probes/{probe_id}/heartbeat",
                                json={"status": "online", "metadata": {"token_value": "still-fine"}},
                                headers=_headers(probe_id, token))
        assert heartbeat.status_code == 200, heartbeat.text
        # A wrong token is an authentication failure, never a report-guard refusal.
        denied = client.post(f"/api/v1/probes/{probe_id}/data-assets",
                             json=_clean_report(), headers=_headers(probe_id, "wrong-token"))
        assert denied.status_code in (401, 403)
