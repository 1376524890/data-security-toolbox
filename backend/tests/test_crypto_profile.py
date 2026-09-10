from __future__ import annotations

from uuid import uuid4

from app.core.database import SessionLocal
from app.models import AnalysisResult, Asset, PcapRecord, Probe, Task
from app.services.crypto_profile import build_crypto_profile


def _seed_probe(name: str, services: list[dict]) -> int:
    with SessionLocal() as db:
        probe = Probe(name=name, hostname="host", ip_address="10.0.0.1", extra={"services": services}, status="online")
        db.add(probe)
        db.commit()
        return probe.id


def _seed_asset(probe_id: int, service: str, port: int, banner: str) -> None:
    with SessionLocal() as db:
        db.add(Asset(
            probe_id=probe_id,
            ip="10.0.0.1",
            hostname="host",
            port=port,
            protocol="tcp",
            service=service,
            asset_type="database" if service in {"mysql", "redis"} else "web",
            risk_level="High",
            extra={"banner": banner, "ip": "10.0.0.1"},
        ))
        db.commit()


def _seed_tls_handshake(probe_id: int) -> None:
    with SessionLocal() as db:
        pcap = PcapRecord(probe_id=probe_id, segment_id="crypto-seg-1", filename="c.pcap", storage_path="/tmp/c.pcap", size=100, sha256="a" * 64, ingest_status="ingested", analysis_status="analyzed")
        db.add(pcap)
        db.flush()
        task = Task(kind="pcap", status="Success", payload={"pcap_id": pcap.id})
        db.add(task)
        db.flush()
        db.add(AnalysisResult(
            task_id=task.id,
            module="protocol_details",
            content={"tls": {"handshakes": [
                {"type": "ClientHello", "cipher": "0x1302,0x1301", "sni": "example.com"},
                {"type": "ServerHello", "cipher": "0x1302", "sni": "example.com"},
            ]}},
        ))
        db.commit()


def test_build_crypto_profile_detects_algorithms_and_weak_auth() -> None:
    probe_id = _seed_probe(f"crypto-probe-{uuid4().hex[:8]}", [{"port": 3306, "service": "mysql"}])
    _seed_asset(probe_id, "mysql", 3306, "5.7.40 noauth Authentication not required")
    _seed_asset(probe_id, "ssh", 22, "SSH-2.0-OpenSSH_9.6")
    _seed_tls_handshake(probe_id)

    with SessionLocal() as db:
        profile = build_crypto_profile(db, probe_id)

    cfg = profile["config"]
    assert "TLS_AES_256_GCM_SHA384" in cfg["cipherSuites"]
    assert "TLSv1.3" in cfg["protocols"]
    assert "AES-256" in cfg["algorithms"]
    assert "Ed25519" in cfg["algorithms"]  # from SSH banner

    signals = profile["passwordSignals"]
    assert any(s["type"] == "weak_auth" and s["service"] == "mysql" for s in signals)
    assert profile["serviceCount"] >= 2
    assert profile["coverage"]["algorithms"] == "detected"
    assert any("MySQL" in t for t in profile["passwordTypes"])


def test_build_crypto_profile_empty_probe_uses_defaults() -> None:
    probe_id = _seed_probe(f"empty-probe-{uuid4().hex[:8]}", [])
    with SessionLocal() as db:
        profile = build_crypto_profile(db, probe_id)
    assert profile["config"]["algorithms"] == []
    assert profile["config"]["cipherSuites"] == []
    assert profile["coverage"]["algorithms"] == "default"
    assert profile["passwordSignals"] == []
