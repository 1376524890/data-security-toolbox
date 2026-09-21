"""Stage 3 integration: the probe scan is bounded, incremental and honest.

These assert the properties an operator actually depends on: a second scan of
unchanged files does not re-read them, a rule update forces a re-read, a large
file is not examined only at its head, and a scan that hit a limit never reports
a complete scope.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

from probe import data_assets  # noqa: E402

MIB = 1024 * 1024
PHONE = "13800138000"


def _config(root: Path, cache: Path, **overrides) -> dict:
    """Scan ``root`` only.

    The cache deliberately lives outside the scan root: a probe stores its state
    in ``/var/lib`` and never inside the data it is inventorying.
    """
    config = {
        "paths": [str(root)],
        "max_files": 50,
        "max_depth": 3,
        "include_databases": False,
        "cache_path": str(cache),
        "ruleset_version": "builtin-1",
    }
    config.update(overrides)
    return config


def _file_assets(report: dict) -> list[dict]:
    return [item for item in report["assets"] if item["asset_type"] != "directory"]


def _write_tree(root: Path) -> None:
    (root / "customers.csv").write_text(
        f"id,phone\n1,{PHONE}\n2,{PHONE}\n", encoding="utf-8")
    (root / "notes.txt").write_text(f"contact {PHONE}\n", encoding="utf-8")


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    """(scan root, cache path) - separate trees so the cache is never scanned."""
    root = tmp_path / "files"
    root.mkdir(parents=True, exist_ok=True)
    return root, tmp_path / "state" / "cache.sqlite"


def test_report_carries_real_coverage_and_scope_completeness(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache))
    coverage = report["coverage"]
    assert coverage["files_analyzed"] == 2
    assert coverage["bytes_read"] > 0
    assert coverage["complete_scope"] is True
    assert coverage["termination_reason"] == "complete"
    assert report["complete"] is True


def test_a_scan_that_hits_a_limit_never_claims_a_complete_scope(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache, max_files=1))
    assert report["complete"] is False
    assert report["coverage"]["complete_scope"] is False
    assert report["coverage"]["termination_reason"] == "file_budget"


def test_a_byte_limit_stops_the_scan_and_is_recorded(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache, max_bytes_read=1024))
    assert report["coverage"]["complete_scope"] is False
    assert report["coverage"]["termination_reason"] == "byte_budget"


def test_a_file_sampled_past_the_row_limit_does_not_end_the_walk(tmp_path: Path) -> None:
    """Content truncation is not an enumeration stop.

    A real /var scan came back with 9 assets because ``/var/backups/dpkg.status.0``
    pushed the shared row counter over its cap and the walker read that as the end
    of the scope. The long file may only cost itself its sample.
    """
    root, cache = _roots(tmp_path)
    nested = root / "nested"
    nested.mkdir()
    (root / "dpkg.status.0").write_text(
        "\n".join(f"Package: pkg-{index}" for index in range(4000)), encoding="utf-8")
    (nested / "customers.csv").write_text(f"id,phone\n1,{PHONE}\n", encoding="utf-8")

    report = data_assets.discover_data_assets(_config(root, cache))
    names = {item["name"] for item in _file_assets(report)}
    assert {"dpkg.status.0", "customers.csv"} <= names, "the walk must continue past a long file"
    assert any(item["asset_type"] == "directory" for item in report["assets"])

    coverage = report["coverage"]
    assert coverage["rows_read"] > 25 * 64
    assert coverage["enumeration_complete"] is True
    assert coverage["content_complete"] is False
    assert coverage["termination_reason"] == "row_budget"
    # Still not complete: nothing may be retired off a report with a short sample.
    assert coverage["complete_scope"] is False
    assert report["complete"] is False
    assert report["completed_scope"] is False


def test_a_stop_event_cancels_and_marks_the_scan_incomplete(tmp_path: Path) -> None:
    import threading

    root, cache = _roots(tmp_path)
    _write_tree(root)
    stop = threading.Event()
    stop.set()
    report = data_assets.discover_data_assets(_config(root, cache), stop)
    assert report["complete"] is False
    assert report["coverage"]["termination_reason"] == "cancelled"
    assert report["coverage"]["complete_scope"] is False


def test_second_scan_reuses_the_cache_instead_of_re_reading(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    first = data_assets.discover_data_assets(_config(root, cache))
    assert first["coverage"]["cache"]["hits"] == 0
    assert first["coverage"]["cache"]["writes"] >= 2

    second = data_assets.discover_data_assets(_config(root, cache))
    stats = second["coverage"]["cache"]
    assert stats["hits"] == 2, "an unchanged file must not be analysed twice"
    assert stats["writes"] == 0, "a cache hit must not be written back"
    # The cached record is still the real one, and it says it came from the cache.
    cached = [item for item in _file_assets(second) if item["evidence"].get("cached")]
    assert len(cached) == 2
    assert any("phone" in item["categories"] for item in cached)


def test_a_rule_set_change_forces_a_re_read(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    data_assets.discover_data_assets(_config(root, cache))
    updated = data_assets.discover_data_assets(_config(root, cache, ruleset_version="rel-2"))
    stats = updated["coverage"]["cache"]
    assert stats["hits"] == 0
    assert stats["misses"] >= 2, "a new rule version must invalidate every cached result"


def test_a_configuration_change_that_affects_analysis_forces_a_re_read(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    data_assets.discover_data_assets(_config(root, cache))
    changed = data_assets.discover_data_assets(
        _config(root, cache, max_sample_rows=5, sample_block_size=8192))
    assert changed["coverage"]["cache"]["hits"] == 0


def test_a_large_file_is_sampled_beyond_its_head(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    path = root / "app.log"
    path.write_bytes(b"filler line\n" * 60_000 + f"phone={PHONE}\n".encode())
    report = data_assets.discover_data_assets(_config(root, cache))
    record = _file_assets(report)[0]
    assert record["evidence"]["coverage"] == "partial"
    # The value sits at the tail, so only multi-position sampling can find it.
    assert "phone" in record["categories"]


def test_a_large_file_gets_a_partial_fingerprint_and_no_full_hash(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    path = root / "big.bin"
    path.write_bytes(bytes(range(256)) * 40_000)  # ~10 MiB
    report = data_assets.discover_data_assets(_config(root, cache, max_full_hash_size=MIB))
    record = _file_assets(report)[0]
    fingerprint = record["evidence"]["fingerprint"]
    assert fingerprint["hash_type"] == "PARTIAL_FINGERPRINT"
    assert fingerprint["partial"] is True
    assert record["sha256"] == "", "a partial fingerprint must never fill the sha256 field"
    assert fingerprint["blocks"], "the sampled layout is recorded with the digest"
    assert fingerprint["bytes_read"] < path.stat().st_size
    # The digest itself has to travel: without it the platform can only fall back
    # to a scope-local identity and no large file can ever be a candidate copy.
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint["value"] or ""), fingerprint["value"]
    assert fingerprint["is_full"] is False
    assert fingerprint["version"]
    # Structure only - the digest is never the bytes it was computed from.
    assert "ID_CARD" not in json.dumps(fingerprint)


def test_a_full_hash_is_reported_as_full_not_as_a_candidate(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache))
    csv_record = next(item for item in _file_assets(report) if item["name"] == "customers.csv")
    fingerprint = csv_record["evidence"]["fingerprint"]
    assert fingerprint["is_full"] is True
    assert fingerprint["value"] == csv_record["sha256"]


def test_a_small_file_still_gets_a_full_hash(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache))
    csv_record = next(item for item in _file_assets(report) if item["name"] == "customers.csv")
    assert csv_record["sha256"]
    assert csv_record["evidence"]["fingerprint"]["hash_type"] == "FULL_SHA256"
    assert csv_record["evidence"]["fingerprint"]["partial"] is False


def test_the_byte_budget_bounds_the_whole_scan(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    for index in range(10):
        (root / f"file{index}.txt").write_text("x" * 50_000, encoding="utf-8")
    report = data_assets.discover_data_assets(_config(root, cache, max_bytes_read=64 * 1024))
    assert report["coverage"]["bytes_read"] <= 64 * 1024 + 256 * 1024
    assert report["coverage"]["complete_scope"] is False


def test_xlsx_columns_are_read_locally(tmp_path: Path) -> None:
    from openpyxl import Workbook

    root, cache = _roots(tmp_path)
    path = root / "book.xlsx"
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.append(["id", "phone"])
    worksheet.append(["1", PHONE])
    workbook.save(path)
    report = data_assets.discover_data_assets(_config(root, cache))
    record = _file_assets(report)[0]
    assert record["asset_type"] == "table"
    assert {column["name"] for column in record["columns"]} == {"id", "phone"}
    assert "phone" in record["categories"]
    assert record["evidence"]["parser"] == "xlsx"


def test_the_report_returns_the_matched_text_of_a_confirmed_hit(tmp_path: Path) -> None:
    """原文回传 is an explicit operator requirement: the finding must be verifiable.

    What travels is bounded - the value and the line it sits on - never the file.
    """
    import json

    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache))
    csv_asset = next(item for item in _file_assets(report)
                     if item["name"] == "customers.csv")
    phone_hit = next(hit for hit in csv_asset["evidence"]["hits"]
                     if hit["category"] == "phone")
    assert phone_hit["matches"], "a confirmed hit must return what it matched"
    assert phone_hit["matches"][0]["value"] == PHONE
    assert PHONE in phone_hit["matches"][0]["context"]
    assert len(phone_hit["matches"]) <= 3
    # Bounded, not the file: the report carries these strings and nothing else
    # from the sample, and the parser's sample cells stay in memory.
    for asset in report["assets"]:
        assert "values" not in json.dumps(asset.get("evidence", {}))
        for hit in asset.get("evidence", {}).get("hits", []):
            for match in hit.get("matches", []):
                assert len(match["value"]) <= 120 and len(match["context"]) <= 240


def test_a_header_only_hit_returns_no_matched_text(tmp_path: Path) -> None:
    """A column named ``phone`` with no values matched nothing, so it returns nothing."""
    root, cache = _roots(tmp_path)
    (root / "template.csv").write_text("id,phone\n", encoding="utf-8")
    report = data_assets.discover_data_assets(_config(root, cache))
    hits = [hit for item in _file_assets(report)
            for hit in item["evidence"]["hits"] if hit["category"] == "phone"]
    assert hits, "the header is still evidence that the column is worth checking"
    assert all(hit["matches"] == [] for hit in hits)
    assert all(hit["confirmed"] is False for hit in hits)


def test_the_cache_holds_the_bounded_sample_not_the_file(tmp_path: Path) -> None:
    """A cache hit must reproduce the report, so the returned sample is cached too.

    Only the returned strings are: nothing else from the file's content is.
    """
    root, cache = _roots(tmp_path)
    _write_tree(root)
    (root / "notes.txt").write_text(
        f"contact {PHONE}\njust an ordinary prose line\n", encoding="utf-8")
    data_assets.discover_data_assets(_config(root, cache))
    blob = cache.read_bytes()
    assert PHONE.encode() in blob, "the returned sample is what makes a cache hit honest"
    assert b"ordinary prose line" not in blob, "the file itself is never cached"


def test_directory_assets_and_counts_are_still_produced(tmp_path: Path) -> None:
    root, cache = _roots(tmp_path)
    _write_tree(root)
    report = data_assets.discover_data_assets(_config(root, cache))
    assert any(item["asset_type"] == "directory" for item in report["assets"])
    assert report["counts"].get("phone", 0) >= 1
    assert report["scanned_paths"] == [str(root.absolute())]
