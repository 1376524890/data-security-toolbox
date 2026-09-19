from pathlib import Path

from app.integrations.zeek.adapter import ZeekAdapter
from app.integrations.zeek.parser import parse_json_lines


def test_zeek_dns_tunnel_needs_an_aggregated_pattern() -> None:
    """A single long label is a clue; a tunnel is many encoded labels for one domain."""
    isolated = [{"event_type": "dns", "query": "a" * 60, "ts": "2026-01-01T00:00:00Z"}]
    assert not any(item.rule_id == "ZEK_DNS_TUNNEL_001"
                   for item in ZeekAdapter().adapt(isolated).findings)

    encoded = ["a1b2c3d4e5f6g7h8", "i9j0k1l2m3n4o5p6", "q7r8s9t0u1v2w3x4"]
    records = [{"event_type": "dns", "id.orig_h": "10.0.0.5",
                "query": f"{encoded[index % 3]}.tunnel.example.com",
                "ts": f"2026-01-01T00:00:{index:02d}Z"} for index in range(20)]
    tunnel = [item for item in ZeekAdapter().adapt(records).findings
              if item.rule_id == "ZEK_DNS_TUNNEL_001"]
    assert len(tunnel) == 1
    assert tunnel[0].evidence["src_ip"] == "10.0.0.5"
    assert tunnel[0].evidence["query_count"] >= 20


def test_zeek_tls_invalid() -> None:
    records = [{"event_type": "ssl", "server_name": "bad.example", "validation_status": "self signed", "ts": "2026-01-01T00:00:00Z"}]
    result = ZeekAdapter().adapt(records)
    assert any(item.rule_id == "ZEK_TLS_INVALID_001" for item in result.findings)


def test_zeek_http_suspicious_ua() -> None:
    records = [{"event_type": "http", "method": "GET", "uri": "/", "user_agent": "sqlmap/1.7", "ts": "2026-01-01T00:00:00Z"}]
    result = ZeekAdapter().adapt(records)
    assert any(item.rule_id == "ZEK_HTTP_UA_001" for item in result.findings)


def test_zeek_http_upload_needs_a_file() -> None:
    routine = [{"event_type": "http", "method": "POST", "uri": "/login.php",
                "user_agent": "Mozilla", "ts": "2026-01-01T00:00:00Z"}]
    assert not any(item.rule_id == "ZEK_HTTP_UPLOAD_001"
                   for item in ZeekAdapter().adapt(routine).findings)

    upload = [{"event_type": "http", "method": "POST", "uri": "/upload",
               "filename": "shell.php", "mime_type": "application/x-php",
               "user_agent": "Mozilla", "ts": "2026-01-01T00:00:00Z"}]
    assert any(item.rule_id == "ZEK_HTTP_UPLOAD_001"
               for item in ZeekAdapter().adapt(upload).findings)


def test_zeek_files_executable() -> None:
    records = [{"event_type": "files", "filename": "payload.exe", "mime_type": "application/x-msdownload", "ts": "2026-01-01T00:00:00Z"}]
    result = ZeekAdapter().adapt(records)
    assert any(item.rule_id == "ZEK_FILE_SUSPICIOUS_001" for item in result.findings)


def test_zeek_weird() -> None:
    records = [{"event_type": "weird", "name": "SSL_invalid_ServerName", "ts": "2026-01-01T00:00:00Z"}]
    result = ZeekAdapter().adapt(records)
    assert any(item.rule_id == "ZEK_WEIRD_001" for item in result.findings)


def test_zeek_parse_json_lines(tmp_path: Path) -> None:
    path = tmp_path / "dns.json"
    path.write_text('{"query":"example.com","ts":1}\n', encoding="utf-8")
    records = parse_json_lines(path.read_text(), str(path))
    assert records[0]["event_type"] == "dns"
