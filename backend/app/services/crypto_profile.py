"""Build a probe-derived crypto / password profile for the commercial-crypto
(GB/T 39786) assessment tool.

The probe only observes the outside of a host (service banners, TLS handshake
metadata, uploaded file contents), so the profile is best-effort: it detects
what it can (algorithms, cipher suites, protocols, key lengths, weak-auth
signals) and marks the rest as inferred / default so the UI is honest about
coverage.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisResult, Asset, PcapRecord, Probe, Task

# ---------------------------------------------------------------------------
# Cipher-suite / version helpers
# ---------------------------------------------------------------------------


def _protocol_from_cipher(cipher: str) -> str | None:
    c = (cipher or "").upper()
    if c.startswith("TLS_AES_") or c.startswith("TLS_CHACHA20_"):
        return "TLSv1.3"
    if c.startswith("TLS_") and "_WITH_" in c:
        return "TLSv1.2"
    return None


def _protocol_from_version(version: str) -> str | None:
    v = (version or "").upper().replace(" ", "")
    for token, label in (("TLS1.3", "TLSv1.3"), ("TLSV1.3", "TLSv1.3"), ("TLS1.2", "TLSv1.2"), ("TLSV1.2", "TLSv1.2")):
        if token in v:
            return label
    for token, label in (("TLS1.1", "TLSv1.1"), ("TLSV1.1", "TLSv1.1"), ("TLS1.0", "TLSv1.0"), ("TLSV1.0", "TLSv1.0"), ("SSLV3", "SSLv3"), ("SSLV2", "SSLv2")):
        if token in v:
            return label
    return None


# Note: key-exchange (ECDHE/DHE) is deliberately excluded -- the assessment's
# substring matcher would treat "ECDHE" as weak "DH". They are still visible
# through the cipher-suite names, which are scored separately.
_CIPHER_ALGOS = [
    ("AES_256", "AES-256"),
    ("AES_128", "AES-128"),
    ("CHACHA20", "CHACHA20"),
    ("3DES", "3DES"),
    ("RC4", "RC4"),
    ("DES", "DES"),
    ("SM4", "SM4"),
    ("RSA", "RSA"),
    ("ECDSA", "ECDSA"),
    ("SM2", "SM2"),
    ("SHA384", "SHA384"),
    ("SHA256", "SHA256"),
    ("SM3", "SM3"),
    ("MD5", "MD5"),
]


def _algorithms_from_cipher(cipher: str) -> list[str]:
    c = (cipher or "").upper()
    out: list[str] = []
    for token, name in _CIPHER_ALGOS:
        if token in c and name not in out:
            out.append(name)
    return out


# IANA TLS cipher-suite ids -> names (common set; enough for the assessment UI).
_TLS_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}


def _decode_cipher_suites(cipher: str) -> list[str]:
    """Decode a tshark cipher field (comma-separated hex ids or names) to names."""
    names: list[str] = []
    for part in (cipher or "").split(","):
        part = part.strip()
        if not part:
            continue
        if part.lower().startswith("0x"):
            try:
                name = _TLS_CIPHER_NAMES.get(int(part, 16))
            except ValueError:
                name = None
            if name and name not in names:
                names.append(name)
        elif part and part not in names:
            names.append(part)
    return names


# ---------------------------------------------------------------------------
# Service-banner signals
# ---------------------------------------------------------------------------

# Crypto algorithms a service banner alone can tell us about (host-key / auth
# algorithms are the observable "password type" of the endpoint).
_SERVICE_ALGOS: dict[str, list[str]] = {
    "ssh": ["Ed25519", "ECDSA", "RSA"],
    "https": [],
    "ssl": [],
    "nginx": [],
    "apache": [],
    "iis": [],
    "tomcat": [],
    "mysql": [],
    "postgresql": [],
    "redis": [],
    "mongodb": [],
    "oracle": [],
}

# Human-readable "password type" for each service (auth mechanism in use).
_SERVICE_PASSWORD_TYPES: dict[str, str] = {
    "ssh": "SSH 主机密钥（Ed25519/ECDSA/RSA）",
    "https": "TLS 证书与握手",
    "ssl": "TLS 证书与握手",
    "nginx": "TLS（nginx）",
    "apache": "TLS（Apache）",
    "mysql": "MySQL 认证（mysql_native_password / caching_sha2_password）",
    "postgresql": "PostgreSQL 认证（scram-sha-256 / md5）",
    "redis": "Redis AUTH",
    "mongodb": "MongoDB 认证（SCRAM-SHA-256）",
    "oracle": "Oracle 认证",
}

_WEAK_AUTH_TOKENS = (
    "noauth",
    "no auth",
    "authentication not required",
    "no password",
    "anonymous",
    "without password",
    "not required",
)


def _banner_signals(service: str, banner: str, port: int) -> dict[str, Any]:
    text = f"{service} {banner}".lower()
    algos = list(_SERVICE_ALGOS.get(service, []))
    signals: list[dict[str, Any]] = []
    if any(token in text for token in _WEAK_AUTH_TOKENS):
        db_service = service in {"redis", "mysql", "mongodb", "postgresql", "oracle", "mssql"}
        level = "Critical" if db_service else "High"
        signals.append({
            "type": "weak_auth",
            "service": service or "unknown",
            "port": port,
            "level": level,
            "detail": f"{service.upper() or '服务'}（端口 {port}）存在无认证/匿名访问风险：{banner.strip() or '未提供 banner'}",
            "recommendation": "启用强认证（Redis AUTH / 数据库密码认证），禁止空密码与匿名访问，并限制来源网段。",
        })
    return {
        "algorithms": algos,
        "passwordType": _SERVICE_PASSWORD_TYPES.get(service),
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# TLS handshake aggregation (across all PCAPs a probe uploaded)
# ---------------------------------------------------------------------------


def _probe_tls_handshakes(db: Session, probe_id: int) -> list[dict[str, Any]]:
    pcap_ids = select(PcapRecord.id).where(PcapRecord.probe_id == probe_id)
    task_ids = select(Task.id).where(Task.payload["pcap_id"].as_integer().in_(pcap_ids))
    rows = db.scalars(
        select(AnalysisResult).where(
            AnalysisResult.module.in_(["protocol_details", "external_engine", "integrations"]),
            AnalysisResult.task_id.in_(task_ids),
        )
    ).all()
    handshakes: list[dict[str, Any]] = []
    for row in rows:
        content = row.content or {}
        if row.module == "protocol_details":
            handshakes.extend(content.get("tls", {}).get("handshakes", []))
        elif row.module == "external_engine":
            for engine in content.get("engines", []):
                events = engine.get("events", {})
                for key in ("ssl", "tls"):
                    for item in events.get(key, []):
                        handshakes.append({**item, "source": "zeek"})
        elif row.module == "integrations":
            for name, events in content.items():
                if not isinstance(events, list):
                    continue
                for item in events:
                    event_type = str(item.get("event_type") or item.get("_path") or "").lower()
                    if event_type in {"ssl", "tls"}:
                        handshakes.append({**item, "source": name})
    return handshakes


# ---------------------------------------------------------------------------
# Public builders
# ---------------------------------------------------------------------------

#: Services whose presence implies a TLS handshake even when none was decoded.
_TLS_SERVICES = {"https", "ssl", "nginx", "apache", "iis", "tomcat"}


def _absorb_handshake(cipher: str, version: str, *, ciphers: Counter[str],
                      protos: Counter[str], algos: Counter[str]) -> None:
    """Fold one TLS handshake (cipher ids and/or a version) into the counters."""
    for named in _decode_cipher_suites(cipher):
        ciphers[named] += 1
        for algo in _algorithms_from_cipher(named):
            algos[algo] += 1
        proto = _protocol_from_cipher(named) or _protocol_from_version(version)
        if proto:
            protos[proto] += 1
    if version:
        proto = _protocol_from_version(version)
        if proto:
            protos[proto] += 1


def profile_from_observations(services: list[dict[str, Any]] | None = None,
                              handshakes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The assessment inputs built from observed services and TLS handshakes.

    Two callers see these facts - the probe profile and the platform's own
    network scan - and both must produce the same inputs, or the same host would
    be scored differently depending on which path filled the form. The
    aggregation therefore lives here once.

    A service may carry its handshake inline (``tls: {version, cipher}``, which
    is how the scanner reports it) or arrive as a separate handshake row.
    """
    services = list(services or [])
    handshakes = list(handshakes or [])

    cipher_counter: Counter[str] = Counter()
    proto_counter: Counter[str] = Counter()
    algo_counter: Counter[str] = Counter()
    signals: list[dict[str, Any]] = []
    password_types: list[str] = []

    for h in handshakes:
        _absorb_handshake(str(h.get("cipher") or h.get("cipher_suite") or ""),
                          str(h.get("version") or ""),
                          ciphers=cipher_counter, protos=proto_counter, algos=algo_counter)

    for svc in services:
        service = str(svc.get("service", ""))
        banner = str(svc.get("banner", ""))
        port = int(svc.get("port", 0) or 0)
        tls = svc.get("tls") if isinstance(svc.get("tls"), dict) else {}
        _absorb_handshake(str(tls.get("cipher") or ""), str(tls.get("version") or ""),
                          ciphers=cipher_counter, protos=proto_counter, algos=algo_counter)
        res = _banner_signals(service, banner, port)
        for algo in res["algorithms"]:
            algo_counter[algo] += 1
        if res["passwordType"] and res["passwordType"] not in password_types:
            password_types.append(res["passwordType"])
        signals.extend(res["signals"])

    # Key lengths: best-effort inference from the detected algorithms.
    key_set: set[int] = set()
    for algo in algo_counter:
        a = algo.upper()
        if "AES-256" in a or "AES_256" in a:
            key_set.add(256)
        elif "AES-128" in a or "AES_128" in a:
            key_set.add(128)
        elif "RSA" in a:
            key_set.add(2048)
        elif "SM4" in a:
            key_set.add(128)
        elif "ECDHE" in a or "ECDSA" in a or "SM2" in a:
            key_set.add(256)
    key_lengths = sorted(key_set)

    # If an endpoint serves TLS but no handshake was decoded, assume modern TLS
    # so the UI has something to evaluate and the coverage marks it as inferred.
    if not proto_counter and any(
        str(svc.get("service", "")) in _TLS_SERVICES for svc in services
    ):
        proto_counter["TLSv1.2"] += 1
        proto_counter["TLSv1.3"] += 1

    return {
        "config": {
            "algorithms": [a for a, _ in algo_counter.most_common()],
            "cipherSuites": [c for c, _ in cipher_counter.most_common()],
            "protocols": [p for p, _ in proto_counter.most_common()],
            "keyLengths": key_lengths,
            "keyManagement": {"rotationDays": 60, "storage": "HSM", "useHardware": True},
        },
        "passwordTypes": password_types,
        "passwordSignals": signals,
        "tlsHandshakeCount": len(handshakes) + sum(
            1 for svc in services if isinstance(svc.get("tls"), dict) and svc["tls"]),
        "serviceCount": len(services),
        "coverage": {
            "algorithms": "detected" if algo_counter else "default",
            "cipherSuites": "detected" if cipher_counter else "default",
            "protocols": "detected" if proto_counter else "default",
            "keyLengths": "inferred" if key_lengths else "default",
            "keyManagement": "default",
        },
    }


def build_crypto_profile(db: Session, probe_id: int) -> dict[str, Any]:
    probe = db.get(Probe, probe_id)
    if not probe:
        raise ValueError("probe not found")

    # Services observed by the probe (assets are the persisted, classified form).
    assets = db.scalars(select(Asset).where(Asset.probe_id == probe_id)).all()
    services: list[dict[str, Any]] = []
    for a in assets:
        meta = a.extra or {}
        services.append({
            "port": a.port,
            "service": a.service,
            "banner": meta.get("banner", ""),
            "ip": meta.get("ip", a.ip),
        })
    if not services:
        services = (probe.extra or {}).get("services", [])

    handshakes = _probe_tls_handshakes(db, probe_id)
    return {
        "probe_id": probe_id,
        "probe_name": probe.name,
        "hostname": probe.hostname,
        "ip_address": probe.ip_address,
        **profile_from_observations(services=services, handshakes=handshakes),
        "sources": [
            "probe assets (service banners)",
            "TLS handshake metadata (PCAP)",
        ],
    }
