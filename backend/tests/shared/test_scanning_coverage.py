"""The sampler must not duplicate, drop or over-claim what it read."""
from pathlib import Path

from shared.scanning.budget import ScanBudget
from shared.scanning.parsers.csv_tsv import parse
from shared.scanning.sampler import sample_text


def test_final_line_without_a_newline_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "tail.txt"
    data = b"normal line\nlast@example.com"
    path.write_bytes(data)
    sample = sample_text(path, len(data), budget=ScanBudget())
    assert "last@example.com" in sample.text
    assert sample.coverage == "complete"


def test_overlapping_windows_are_not_counted_twice(tmp_path: Path) -> None:
    path = tmp_path / "small.txt"
    data = b"xxx\n" * 40  # 160 bytes: the five 64-byte windows overlap.
    path.write_bytes(data)
    sample = sample_text(path, len(data), budget=ScanBudget(), block_size=64)
    assert sample.text.count("xxx") == 40
    assert sample.bytes_read == len(data)
    assert sample.coverage == "complete"


def test_sampled_large_file_reports_partial(tmp_path: Path) -> None:
    path = tmp_path / "large.txt"
    data = b"".join(f"line-{index:06d}-xxxxxxxxxxxxxxxx\n".encode() for index in range(20000))
    path.write_bytes(data)
    sample = sample_text(path, len(data), budget=ScanBudget(), block_size=4096)
    assert sample.coverage == "partial"
    assert sample.bytes_read < len(data)


def test_clipped_long_line_is_marked_partial(tmp_path: Path) -> None:
    path = tmp_path / "long.txt"
    data = b"a" * 9000 + b"\nshort\n"
    path.write_bytes(data)
    sample = sample_text(path, len(data), budget=ScanBudget(), block_size=64 * 1024)
    assert sample.line_truncated is True
    assert sample.coverage == "partial"
    assert sample.termination_reason == "line_truncated"


def test_csv_over_the_row_limit_is_partial(tmp_path: Path) -> None:
    path = tmp_path / "rows.csv"
    rows = ["phone"] + [f"1380013800{index}" for index in range(31)]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result = parse(path, path.stat().st_size, budget=ScanBudget(), rows=25)
    assert result.coverage == "partial"
    assert result.termination_reason == "row_limit"
    assert result.rows_read == 25
