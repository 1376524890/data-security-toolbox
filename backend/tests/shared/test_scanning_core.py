"""Budget, fingerprint, type probe, sampler and cache - the bounded primitives.

The recurring theme: no limit may be exceeded by moving work between stages, and
nothing here may report more certainty than it actually has.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from shared.scanning import magic, sampler
from shared.scanning.budget import (
    TERMINATION_BYTES,
    TERMINATION_COMPLETE,
    TERMINATION_DIRECTORIES,
    TERMINATION_FILES,
    TERMINATION_TIMEOUT,
    BudgetExceeded,
    ScanBudget,
)
from shared.scanning.cache import AnalysisCache, config_fingerprint, key_for
from shared.scanning.fingerprint import (
    FULL_SHA256,
    PARTIAL_FINGERPRINT,
    PARTIAL_VERSION,
    block_layout,
    full_sha256,
    identify,
    partial_fingerprint,
)

MIB = 1024 * 1024


# --- budget ----------------------------------------------------------------

def test_defaults_match_the_shipped_scanner_behaviour() -> None:
    budget = ScanBudget()
    assert budget.max_files == 200
    assert budget.max_depth == 3
    assert budget.max_dirs == 500
    assert budget.max_single_file == 2 * MIB
    assert budget.max_full_hash == 8 * MIB
    assert budget.max_runtime == 120
    assert budget.max_rows == 25
    assert budget.limit("large_file_sampling") is True


def test_limits_are_clamped_to_their_ceilings() -> None:
    budget = ScanBudget({"max_files": 99999, "max_depth": 99, "max_runtime_seconds": 99999})
    assert budget.max_files == 2000
    assert budget.max_depth == 8
    assert budget.max_runtime == 1800


def test_every_stage_draws_from_the_same_byte_counter(tmp_path: Path) -> None:
    budget = ScanBudget({"max_bytes_read": 64})
    budget.spend_bytes(32)
    with pytest.raises(BudgetExceeded) as excinfo:
        budget.spend_bytes(32) or budget.check()
    assert excinfo.value.reason == TERMINATION_BYTES
    assert budget.termination_reason == TERMINATION_BYTES


def test_file_and_directory_limits_stop_the_scan() -> None:
    budget = ScanBudget({"max_files": 2, "max_dirs": 1})
    budget.note_file()
    budget.note_file()
    with pytest.raises(BudgetExceeded) as excinfo:
        budget.note_file()
    assert excinfo.value.reason == TERMINATION_FILES
    assert budget.termination_reason == TERMINATION_FILES

    budget = ScanBudget({"max_dirs": 1})
    budget.note_directory()
    with pytest.raises(BudgetExceeded) as excinfo:
        budget.note_directory()
    assert excinfo.value.reason == TERMINATION_DIRECTORIES


def test_the_time_budget_is_monotonic_and_enforced() -> None:
    budget = ScanBudget({"max_runtime_seconds": 1})
    assert budget.remaining_seconds() <= 1.0
    budget.deadline = time.monotonic() - 1
    with pytest.raises(BudgetExceeded) as excinfo:
        budget.check()
    assert excinfo.value.reason == TERMINATION_TIMEOUT
    assert budget.complete is False


def test_a_stop_event_cancels_mid_scan() -> None:
    stop = threading.Event()
    budget = ScanBudget({"max_runtime_seconds": 600})
    budget.attach_stop_event(stop)
    budget.check()
    stop.set()
    with pytest.raises(BudgetExceeded):
        budget.check()
    assert budget.termination_reason == "cancelled"


def test_only_the_first_termination_reason_is_kept() -> None:
    budget = ScanBudget()
    budget.stop(TERMINATION_FILES, "files")
    budget.stop(TERMINATION_TIMEOUT, "time")
    assert budget.termination_reason == TERMINATION_FILES
    assert budget.coverage()["termination_detail"] == "files"


def test_coverage_reports_real_counters_and_completeness() -> None:
    budget = ScanBudget()
    budget.note_file()
    budget.note_directory()
    budget.spend_bytes(1024)
    budget.spend_rows(3)
    budget.note_skip()
    coverage = budget.coverage()
    assert coverage["files_analyzed"] == 1
    assert coverage["files_discovered"] == 2
    assert coverage["directories_scanned"] == 1
    assert coverage["bytes_read"] == 1024
    assert coverage["complete_scope"] is True
    assert coverage["termination_reason"] == TERMINATION_COMPLETE


# --- fingerprint -----------------------------------------------------------

def test_small_file_gets_a_full_hash_and_large_file_gets_a_fingerprint(tmp_path: Path) -> None:
    small = tmp_path / "small.csv"
    small.write_bytes(b"phone,id\n13800138000,110101199003076173\n")
    budget = ScanBudget()
    full = identify(small, small.stat().st_size, max_full_hash_size=8 * MIB, budget=budget)
    assert full.hash_type == FULL_SHA256 and full.is_full
    assert full.bytes_read == small.stat().st_size

    large = tmp_path / "large.log"
    large.write_bytes(os.urandom(3 * MIB))
    partial = identify(large, large.stat().st_size, max_full_hash_size=MIB, block_size=64 * 1024, budget=budget)
    assert partial.hash_type == PARTIAL_FINGERPRINT
    assert not partial.is_full
    assert partial.version == PARTIAL_VERSION
    # Bounded: five blocks, far less than the whole file.
    assert partial.bytes_read <= 5 * 64 * 1024
    assert len(partial.blocks) == 5


def test_a_partial_fingerprint_is_never_reported_as_a_full_hash(tmp_path: Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(bytes(range(256)) * 40_000)
    fingerprint = partial_fingerprint(path, path.stat().st_size, block_size=4096)
    evidence = fingerprint.as_evidence()
    assert evidence["hash_type"] == PARTIAL_FINGERPRINT
    assert FULL_SHA256 not in str(evidence["hash_type"])
    assert evidence["blocks"], "the layout is recorded so the digest is reproducible"


def test_full_hash_refuses_a_file_over_the_ceiling(tmp_path: Path) -> None:
    path = tmp_path / "too-big.bin"
    path.write_bytes(b"x" * 4096)
    fingerprint = full_sha256(path, path.stat().st_size, limit=1024)
    assert fingerprint.hash_type == ""
    assert fingerprint.reason == "over_full_hash_limit"
    assert fingerprint.stable is False


def test_identical_content_hashes_equal_and_one_changed_byte_does_not(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    payload = b"phone 13800138000\n"
    first.write_bytes(payload)
    second.write_bytes(payload)
    left = full_sha256(first, first.stat().st_size, limit=MIB)
    right = full_sha256(second, second.stat().st_size, limit=MIB)
    assert left.value == right.value and left.value

    second.write_bytes(payload + b"x")
    changed = full_sha256(second, second.stat().st_size, limit=MIB)
    assert changed.value != left.value


def test_partial_fingerprint_distinguishes_whole_file_identity(tmp_path: Path) -> None:
    path = tmp_path / "sampled.bin"
    body = os.urandom(512 * 1024)
    path.write_bytes(body)
    partial = partial_fingerprint(path, len(body), block_size=4096)
    full = full_sha256(path, len(body), limit=MIB)
    # Same file, different claims: only the full hash may be used for "identical".
    assert partial.value and full.value and partial.value != full.value
    assert partial.hash_type != full.hash_type


def test_block_layout_covers_head_and_tail_without_overlap() -> None:
    size = 1_000_000
    layout = block_layout(size, 64 * 1024)
    offsets = [block["offset"] for block in layout]
    assert offsets[0] == 0
    assert offsets[-1] + layout[-1]["length"] == size
    assert offsets == sorted(offsets)
    for block in layout:
        assert block["offset"] >= 0
        assert block["offset"] + block["length"] <= size
    spans = sorted((block["offset"], block["offset"] + block["length"]) for block in layout)
    for (start, end), (next_start, _) in zip(spans, spans[1:]):
        assert next_start >= end, "sample blocks must not overlap"


def test_tiny_file_yields_one_block_and_empty_file_yields_none(tmp_path: Path) -> None:
    assert block_layout(0) == []
    assert block_layout(10, 64 * 1024) == [{"position": 0, "offset": 0, "length": 10}]


def test_a_file_changing_during_the_read_is_not_called_stable(tmp_path: Path) -> None:
    path = tmp_path / "moving.txt"
    path.write_bytes(b"a" * 2048)

    real_fstat = os.fstat
    calls = {"n": 0}

    def flaky(fd):
        result = real_fstat(fd)
        calls["n"] += 1
        if calls["n"] == 2:
            return os.stat_result((result.st_mode, result.st_ino, result.st_dev, result.st_nlink,
                                   result.st_uid, result.st_gid, result.st_size, 0, 0, 0))
        return result

    import shared.scanning.fingerprint as module

    original = module.os.fstat
    module.os.fstat = flaky
    try:
        fingerprint = full_sha256(path, path.stat().st_size, limit=MIB)
    finally:
        module.os.fstat = original
    assert fingerprint.stable is False
    assert fingerprint.hash_type == ""
    assert fingerprint.reason == "changed_during_read"


# --- magic -----------------------------------------------------------------

@pytest.mark.parametrize(
    "name, head, suffix, kind",
    [
        ("data.csv", b"id,phone\n1,13800138000\n", ".csv", magic.KIND_TABLE),
        ("rows.jsonl", b'{"a": 1}\n', ".jsonl", magic.KIND_TABLE),
        ("dump.sql", b"CREATE TABLE t (a int);\n", ".sql", magic.KIND_TABLE),
        ("archive.zip", b"PK\x03\x04rest", ".zip", magic.KIND_ARCHIVE),
        ("image.png", b"\x89PNG\r\n\x1a\nrest", ".png", magic.KIND_BINARY),
        ("weird.dat", b"plain text payload", ".dat", magic.KIND_TEXT),
        ("agent.log", b"2026-09-16 line\n", ".log", magic.KIND_TEXT),
    ],
)
def test_type_probe_uses_extension_and_content(name: str, head: bytes, suffix: str, kind: str) -> None:
    assert magic.detect(suffix, head, name=name).kind == kind


def test_a_binary_file_with_a_text_extension_is_not_treated_as_text() -> None:
    """`.dat` is a hint; a NUL byte means the file is not decoded."""
    detected = magic.detect(".dat", b"\x00\x01\x02binary", name="payload.dat")
    assert detected.kind == magic.KIND_BINARY
    assert detected.is_text is False
    assert detected.parser == ""


def test_sql_gz_is_recognised_by_name_not_by_a_rewritten_extension() -> None:
    detected = magic.detect(".gz", b"\x1f\x8b\x08\x00", name="dump.sql.gz")
    assert detected.kind == magic.KIND_SQL_GZ
    assert detected.parser == "sql_gz"


def test_zip_archives_are_only_listed_never_unpacked() -> None:
    detected = magic.detect(".zip", b"PK\x03\x04", name="bundle.zip")
    assert detected.kind == magic.KIND_ARCHIVE
    assert detected.parser == ""
    assert "not unpacked" in detected.reason


# --- sampler ---------------------------------------------------------------

def test_sampling_reads_several_positions_of_a_large_text_file(tmp_path: Path) -> None:
    path = tmp_path / "big.log"
    head = b"start 13800138000\n"
    filler = b"x" * (2 * MIB)
    tail = b"end 110101199003076173\n"
    path.write_bytes(head + filler + tail)
    budget = ScanBudget()
    sample = sampler.sample_text(path, path.stat().st_size, budget=budget, block_size=64 * 1024)
    assert sample.positions[0] == 0
    assert len(sample.positions) >= 3
    assert len(sample.text) > 0
    # Bounded: five blocks at most, not the whole file.
    assert sample.bytes_read <= 5 * 64 * 1024
    assert budget.bytes_read == sample.bytes_read


def test_a_small_file_is_read_whole_and_reported_complete(tmp_path: Path) -> None:
    path = tmp_path / "small.txt"
    path.write_text("phone 13800138000\n", encoding="utf-8")
    budget = ScanBudget()
    sample = sampler.sample_text(path, path.stat().st_size, budget=budget, block_size=64 * 1024)
    assert sample.coverage == "complete"
    assert sample.termination_reason == "complete"
    assert "13800138000" in sample.text


def test_partial_last_line_is_dropped_rather_than_reported_as_a_record(tmp_path: Path) -> None:
    path = tmp_path / "cut.log"
    path.write_bytes(b"record one\nrecord two\nrecord thre")
    budget = ScanBudget()
    sample = sampler.sample_text(path, path.stat().st_size, budget=budget, block_size=1024,
                                 whole_file_limit=64)
    assert "record thre" not in sample.text
    assert "record one" in sample.text


def test_sampling_stops_when_the_byte_budget_runs_out(tmp_path: Path) -> None:
    path = tmp_path / "big.log"
    path.write_bytes(b"y" * (MIB))
    budget = ScanBudget({"max_bytes_read": 4096})
    sample = sampler.sample_text(path, path.stat().st_size, budget=budget, block_size=32 * 1024)
    assert sample.coverage == "partial"
    assert sample.termination_reason == TERMINATION_BYTES
    assert budget.bytes_read <= 32 * 1024


def test_gb18030_text_is_decoded(tmp_path: Path) -> None:
    path = tmp_path / "cn.txt"
    path.write_bytes("姓名,手机号\n张三,13800138000\n".encode("gb18030"))
    budget = ScanBudget()
    sample = sampler.sample_text(path, path.stat().st_size, budget=budget, block_size=4096)
    assert "张三" in sample.text


def test_one_enormous_line_cannot_pull_the_whole_sample_into_memory(tmp_path: Path) -> None:
    path = tmp_path / "oneline.txt"
    path.write_bytes(b"a" * 100_000)
    budget = ScanBudget()
    sample = sampler.sample_text(path, path.stat().st_size, budget=budget, block_size=4096)
    assert all(len(line) <= sampler.MAX_LINE_CHARS for line in sample.text.splitlines())


# --- cache -----------------------------------------------------------------

def _stat(path: Path) -> os.stat_result:
    return os.stat(path)


def test_cache_round_trip_and_key_includes_versions(tmp_path: Path) -> None:
    target = tmp_path / "file.csv"
    target.write_text("a,b\n", encoding="utf-8")
    cache = AnalysisCache(tmp_path / "cache.sqlite")
    assert cache.open()
    fingerprint = config_fingerprint({"engine_version": "1.0.0", "ruleset_version": "builtin-1"})
    key = key_for(str(target), _stat(target), engine_version="1.0.0", ruleset_version="builtin-1",
                  fingerprint=fingerprint)
    assert cache.get(key) is None
    cache.put(key, path=str(target), stat=_stat(target), engine_version="1.0.0",
              ruleset_version="builtin-1", fingerprint=fingerprint, payload={"categories": ["phone"]})
    assert cache.get(key) == {"categories": ["phone"]}

    # A rule-set change is a different key: content is re-read, not reused.
    other = key_for(str(target), _stat(target), engine_version="1.0.0", ruleset_version="rel-2",
                    fingerprint=fingerprint)
    assert other != key
    assert cache.get(other) is None
    cache.close()


def test_cache_key_changes_when_the_file_changes(tmp_path: Path) -> None:
    target = tmp_path / "file.csv"
    target.write_text("a,b\n", encoding="utf-8")
    first = key_for(str(target), _stat(target), engine_version="1", ruleset_version="r", fingerprint="f")
    target.write_text("a,b\nc,d\n", encoding="utf-8")
    second = key_for(str(target), _stat(target), engine_version="1", ruleset_version="r", fingerprint="f")
    assert first != second


def test_config_fingerprint_only_tracks_analysis_affecting_settings() -> None:
    base = {"engine_version": "1.0.0", "ruleset_version": "builtin-1", "max_sample_rows": 25}
    assert config_fingerprint(base) == config_fingerprint({**base, "max_files": 200})
    assert config_fingerprint(base) != config_fingerprint({**base, "max_sample_rows": 50})
    assert config_fingerprint(base) != config_fingerprint({**base, "ruleset_version": "rel-2"})


def test_a_corrupt_cache_is_discarded_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "cache.sqlite"
    path.write_bytes(b"this is not a sqlite database" * 40)
    cache = AnalysisCache(path)
    # Opening may fail or succeed depending on where the corruption sits; either
    # way a lookup must return a miss instead of raising.
    cache.open()
    assert cache.get("anything") is None
    cache.close()


def test_a_torn_row_is_a_miss(tmp_path: Path) -> None:
    target = tmp_path / "file.csv"
    target.write_text("a\n", encoding="utf-8")
    cache = AnalysisCache(tmp_path / "cache.sqlite")
    cache.open()
    cache.put("k", path=str(target), stat=_stat(target), engine_version="1", ruleset_version="r",
              fingerprint="f", payload={"ok": True})
    cache._connection.execute("UPDATE analysis_cache SET payload = '{ broken' WHERE key = 'k'")
    cache._connection.commit()
    assert cache.get("k") is None
    assert cache.stats.invalid == 1
    cache.close()


def test_cache_never_stores_file_content(tmp_path: Path) -> None:
    target = tmp_path / "secrets.txt"
    target.write_text("api_key=sk-live-abcdefghijklmnop\n", encoding="utf-8")
    cache = AnalysisCache(tmp_path / "cache.sqlite")
    cache.open()
    cache.put("k", path=str(target), stat=_stat(target), engine_version="1", ruleset_version="r",
              fingerprint="f", payload={"categories": ["secret"], "counts": {"secret": 1}})
    cache.close()
    blob = (tmp_path / "cache.sqlite").read_bytes()
    assert b"sk-live-abcdefghijklmnop" not in blob


def test_cache_capacity_is_bounded(tmp_path: Path) -> None:
    target = tmp_path / "file.csv"
    target.write_text("a\n", encoding="utf-8")
    cache = AnalysisCache(tmp_path / "cache.sqlite", max_entries=5)
    cache.open()
    for index in range(12):
        cache.put(f"k{index}", path=str(target), stat=_stat(target), engine_version="1",
                  ruleset_version="r", fingerprint="f", payload={"i": index})
    count = cache._connection.execute("SELECT COUNT(*) FROM analysis_cache").fetchone()[0]
    assert count <= 5
    cache.close()


def test_purge_drops_rows_for_files_that_no_longer_exist(tmp_path: Path) -> None:
    cache = AnalysisCache(tmp_path / "cache.sqlite")
    cache.open()
    gone = tmp_path / "gone.csv"
    gone.write_text("a\n", encoding="utf-8")
    cache.put("k", path=str(gone), stat=_stat(gone), engine_version="1", ruleset_version="r",
              fingerprint="f", payload={})
    gone.unlink()
    assert cache.purge_missing() == 1
    cache.close()
