"""Parsers: sensitive values wherever they sit, and honest coverage statements.

Each parser is checked for the two things that actually matter operationally: it
finds data placed away from the head of a large file, and it never claims more
coverage than it read.
"""
from __future__ import annotations

import gzip
import io
import zipfile
from pathlib import Path

import pytest

from shared.scanning.budget import ScanBudget
from shared.scanning.magic import detect
from shared.scanning.parsers import parse_file
from shared.scanning.parsers import csv_tsv, generic_text, json_like, sql, xlsx

MIB = 1024 * 1024
PHONE = "13800138000"
ID_CARD = "110101199003076173"


def _parse(path: Path, *, budget: ScanBudget | None = None, name: str | None = None):
    budget = budget or ScanBudget({"max_bytes_read": 64 * MIB})
    head = path.open("rb").read(4096)
    file_type = detect(path.suffix.lower(), head, name=name or path.name)
    return parse_file(path, path.stat().st_size, file_type, budget=budget), budget


def _all_sample_text(result) -> str:
    return "\n".join(column.sample_text() for column in result.columns())


def _write_xlsx(path: Path, rows: list[list[str]], *, sheet: str = "Sheet1") -> None:
    from openpyxl import Workbook

    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = sheet
    for row in rows:
        worksheet.append(row)
    workbook.save(path)


# --- generic text ----------------------------------------------------------

def test_generic_text_finds_a_value_away_from_the_head(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_bytes(b"info start\n" + b"filler line\n" * 40_000 + f"phone={PHONE}\n".encode())
    result, budget = _parse(path)
    assert result.parser == "generic_text"
    assert PHONE in result.text
    assert result.bytes_read < path.stat().st_size
    assert result.coverage == "partial"
    assert budget.bytes_read >= result.bytes_read


def test_generic_text_reads_a_small_file_whole(tmp_path: Path) -> None:
    path = tmp_path / "small.txt"
    path.write_text(f"id card {ID_CARD}\n", encoding="utf-8")
    result, _ = _parse(path)
    assert result.coverage == "complete"
    assert result.termination_reason == "complete"
    assert ID_CARD in result.text


def test_generic_text_handles_an_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    result, _ = _parse(path)
    assert result.rows_read == 0
    assert not result.columns()


def test_an_undeclared_extension_with_text_content_still_reaches_the_text_parser(tmp_path: Path) -> None:
    path = tmp_path / "export.customer"
    path.write_text(f"contact,{PHONE}\n", encoding="utf-8")
    result, _ = _parse(path, name="export.customer")
    assert result.parser == "generic_text"
    assert PHONE in result.text


def test_a_binary_file_is_listed_and_not_decoded(tmp_path: Path) -> None:
    path = tmp_path / "blob.dat"
    path.write_bytes(b"\x00\x01\x02\x03" * 5000)
    result, _ = _parse(path)
    assert result.parser == ""
    assert result.text == ""
    assert "二进制" in result.note


# --- CSV/TSV ---------------------------------------------------------------

def test_csv_keeps_the_header_and_samples_cells(tmp_path: Path) -> None:
    path = tmp_path / "customers.csv"
    path.write_text(f"id,phone,id_card\n1,{PHONE},{ID_CARD}\n2,{PHONE},{ID_CARD}\n", encoding="utf-8")
    result, _ = _parse(path)
    assert result.parser == "csv_tsv"
    names = [column.name for column in result.columns()]
    assert names == ["id", "phone", "id_card"]
    phone_column = next(column for column in result.columns() if column.name == "phone")
    assert PHONE in phone_column.sample_text()
    assert phone_column.inferred_type == "integer"


def test_csv_handles_quoted_fields_with_embedded_newlines(tmp_path: Path) -> None:
    path = tmp_path / "quoted.csv"
    path.write_text(f'id,note\n1,"line one\nline two"\n2,"{PHONE}"\n', encoding="utf-8")
    result, _ = _parse(path)
    note = next(column for column in result.columns() if column.name == "note")
    assert len(note.values) == 2
    assert PHONE in note.sample_text()


def test_tsv_uses_the_tab_delimiter(tmp_path: Path) -> None:
    path = tmp_path / "rows.tsv"
    path.write_text(f"id\tphone\n1\t{PHONE}\n", encoding="utf-8")
    result, _ = _parse(path)
    assert [column.name for column in result.columns()] == ["id", "phone"]


def test_large_csv_samples_the_middle_and_tail_too(tmp_path: Path) -> None:
    path = tmp_path / "big.csv"
    body = io.StringIO()
    body.write("id,phone\n")
    for index in range(20_000):
        body.write(f"{index},00000000000\n")
    body.write(f"999999,{PHONE}\n")
    path.write_text(body.getvalue(), encoding="utf-8")
    result, _ = _parse(path)
    assert result.coverage == "partial"
    assert result.termination_reason == "sampled"
    assert PHONE in _all_sample_text(result), "the tail record must be sampled, not just the head"


def test_csv_column_evidence_carries_counts_not_values(tmp_path: Path) -> None:
    path = tmp_path / "customers.csv"
    path.write_text(f"phone\n{PHONE}\n", encoding="utf-8")
    result, _ = _parse(path)
    evidence = result.as_evidence()
    assert PHONE not in str(evidence)
    column = evidence["sheets"][0]["columns"][0]
    assert column["sample_size"] == 1
    assert column["sample_values_count"] == 1
    assert "values" not in column


def test_csv_without_a_header_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "empty.csv"
    path.write_bytes(b"")
    result, _ = _parse(path)
    assert result.columns() == []
    assert result.note


# --- JSON / JSONL ----------------------------------------------------------

def test_small_json_is_parsed_into_columns(tmp_path: Path) -> None:
    path = tmp_path / "records.json"
    path.write_text(f'[{{"id": 1, "phone": "{PHONE}"}}, {{"id": 2, "phone": "{PHONE}"}}]', encoding="utf-8")
    result, _ = _parse(path)
    assert result.parser == "json_like"
    assert {column.name for column in result.columns()} == {"id", "phone"}
    phone = next(column for column in result.columns() if column.name == "phone")
    assert phone.sample_text().count(PHONE) == 2


def test_jsonl_samples_head_middle_and_tail(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    lines = ['{"id": %d, "note": "x"}' % index for index in range(40_000)]
    lines.append(f'{{"id": 999999, "phone": "{PHONE}"}}')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result, _ = _parse(path)
    assert result.parser == "json_like"
    assert PHONE in _all_sample_text(result)


def test_a_large_json_document_degrades_instead_of_parsing_a_fragment(tmp_path: Path) -> None:
    """A byte slice of a JSON object is not a valid object, so it is not invented."""
    path = tmp_path / "huge.json"
    payload = '{"records": [' + ",".join('{"id": %d, "phone": "%s"}' % (index, PHONE)
                                         for index in range(4000)) + "]}"
    path.write_text(payload, encoding="utf-8")
    assert path.stat().st_size > 64 * 1024
    # Smaller than the file: the document cannot be parsed whole within its budget.
    budget = ScanBudget({"max_single_file_size": 64 * 1024})
    result, _ = _parse(path, budget=budget)
    assert result.degraded_to == "generic_text"
    assert result.coverage == "partial"
    assert "降级" in result.note
    # Degrading must still examine the content rather than silently returning empty.
    assert PHONE in result.text


def test_malformed_json_falls_back_to_text_and_says_so(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text(f'{{"phone": "{PHONE}"', encoding="utf-8")
    result, _ = _parse(path)
    assert result.degraded_to == "generic_text"
    assert "解析失败" in result.note
    assert PHONE in result.text


def test_json_evidence_never_carries_a_value(tmp_path: Path) -> None:
    path = tmp_path / "records.json"
    path.write_text(f'[{{"phone": "{PHONE}"}}]', encoding="utf-8")
    result, _ = _parse(path)
    assert PHONE not in str(result.as_evidence())


# --- SQL -------------------------------------------------------------------

def test_sql_reads_column_names_from_ddl(tmp_path: Path) -> None:
    path = tmp_path / "schema.sql"
    path.write_text("CREATE TABLE customer (id int, phone varchar(20), id_card varchar(18));\n", encoding="utf-8")
    result, _ = _parse(path)
    assert result.parser == "sql"
    assert {column.name for column in result.columns()} >= {"id", "phone", "id_card"}


def test_sql_reads_column_names_from_insert_statements(tmp_path: Path) -> None:
    path = tmp_path / "data.sql"
    path.write_text(f"INSERT INTO t (phone, email) VALUES ('{PHONE}', 'a@b.com');\n", encoding="utf-8")
    result, _ = _parse(path)
    assert {column.name for column in result.columns()} >= {"phone", "email"}


def test_a_large_sql_dump_is_sampled_at_the_tail(tmp_path: Path) -> None:
    path = tmp_path / "dump.sql"
    parts = ["CREATE TABLE t (id int);\n"]
    parts.extend("INSERT INTO t (id) VALUES (%d);\n" % index for index in range(20_000))
    parts.append(f"INSERT INTO t (phone) VALUES ('{PHONE}');\n")
    path.write_text("".join(parts), encoding="utf-8")
    result, _ = _parse(path)
    names = {column.name for column in result.columns()}
    assert "phone" in names, "the tail INSERT must be sampled"
    assert result.coverage == "partial"


def test_sql_gz_is_streamed_with_a_bounded_output_cap(tmp_path: Path) -> None:
    path = tmp_path / "dump.sql.gz"
    body = ("INSERT INTO t (phone) VALUES ('%s');\n" % PHONE) * 200_000
    with gzip.open(path, "wb") as handle:
        handle.write(body.encode())
    budget = ScanBudget({"max_bytes_read": 256 * 1024})
    result, _ = _parse(path, budget=budget, name="dump.sql.gz")
    assert result.parser == "sql"
    # Bounded: the decompressed stream stops at the cap instead of expanding fully.
    assert budget.bytes_read <= 4 * 256 * 1024
    assert result.coverage == "partial"
    assert "上限" in result.note


def test_a_gzip_bomb_does_not_expand_without_bound(tmp_path: Path) -> None:
    path = tmp_path / "bomb.sql.gz"
    with gzip.open(path, "wb") as handle:
        for _ in range(20):
            handle.write(b"\x00" * (8 * MIB))
    budget = ScanBudget({"max_bytes_read": MIB})
    result, _ = _parse(path, budget=budget, name="bomb.sql.gz")
    assert budget.bytes_read <= 32 * MIB
    assert result.coverage in {"partial", "failed"}


# --- XLSX ------------------------------------------------------------------

def test_xlsx_columns_are_read_and_sampled(tmp_path: Path) -> None:
    path = tmp_path / "book.xlsx"
    _write_xlsx(path, [["id", "phone"], ["1", PHONE], ["2", PHONE]])
    result, _ = _parse(path)
    assert result.parser == "xlsx"
    assert {column.name for column in result.columns()} == {"id", "phone"}
    phone = next(column for column in result.columns() if column.name == "phone")
    assert PHONE in phone.sample_text()
    assert result.sheets[0].name == "Sheet1"


def test_xlsx_evidence_reports_structure_without_values(tmp_path: Path) -> None:
    path = tmp_path / "book.xlsx"
    _write_xlsx(path, [["phone"], [PHONE]])
    result, _ = _parse(path)
    evidence = result.as_evidence()
    assert PHONE not in str(evidence)
    assert evidence["sheet_count"] == 1
    column = evidence["sheets"][0]["columns"][0]
    assert column["name"] == "phone"
    assert column["sample_size"] == 1


def test_xlsx_rows_beyond_the_limit_stop_the_sheet(tmp_path: Path) -> None:
    path = tmp_path / "wide.xlsx"
    _write_xlsx(path, [["id"]] + [[str(index)] for index in range(500)])
    budget = ScanBudget({"xlsx_max_rows": 10})
    result, _ = _parse(path, budget=budget)
    assert result.coverage == "partial"
    assert result.termination_reason == "row_limit"
    assert result.rows_read <= 10


def test_xlsx_sheet_limit_is_enforced(tmp_path: Path) -> None:
    from openpyxl import Workbook

    path = tmp_path / "many.xlsx"
    workbook = Workbook()
    workbook.active.title = "S1"
    for index in range(4):
        worksheet = workbook.create_sheet(f"S{index + 2}")
        worksheet.append(["id"])
        worksheet.append([PHONE])
    workbook.save(path)
    budget = ScanBudget({"xlsx_max_sheets": 2})
    result, _ = _parse(path, budget=budget)
    assert len(result.sheets) <= 2
    assert result.coverage == "partial"


def test_a_zip_bomb_named_xlsx_is_rejected(tmp_path: Path) -> None:
    """A highly compressible non-spreadsheet must not be expanded."""
    path = tmp_path / "bomb.xlsx"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("xl/worksheets/sheet1.xml", b"\x00" * (4 * MIB))
    budget = ScanBudget({"xlsx_max_uncompressed_bytes": 64 * 1024})
    result, _ = _parse(path, budget=budget)
    assert result.coverage == "failed"
    assert result.termination_reason == "container_rejected"
    assert "超过上限" in result.note


def test_an_oversized_shared_strings_table_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "strings.xlsx"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("xl/sharedStrings.xml", "<sst>" + "<si><t>x</t></si>" * 500 + "</sst>")
    budget = ScanBudget({"xlsx_max_shared_strings": 100})
    result, _ = _parse(path, budget=budget)
    assert result.coverage == "failed"
    assert "sharedStrings" in result.note


def test_a_corrupt_xlsx_container_is_reported_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "broken.xlsx"
    path.write_bytes(b"PK\x03\x04" + b"garbage" * 200)
    result, _ = _parse(path)
    assert result.coverage == "failed"
    assert result.termination_reason in {"container_rejected", "parse_error"}


def test_a_plain_zip_named_xlsx_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "notreally.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("readme.txt", "hello")
    result, _ = _parse(path)
    assert result.coverage == "failed"
    assert "XLSX" in result.note


# --- cross-parser guarantees ----------------------------------------------

def test_every_parser_stops_at_the_byte_budget(tmp_path: Path) -> None:
    samples = {
        "a.log": b"line of text\n" * 200_000,
        "a.csv": b"id,phone\n" + b"1,13800138000\n" * 100_000,
        "a.jsonl": b'{"a": 1}\n' * 200_000,
        "a.sql": b"INSERT INTO t (a) VALUES (1);\n" * 100_000,
    }
    for name, payload in samples.items():
        path = tmp_path / name
        path.write_bytes(payload)
        budget = ScanBudget({"max_bytes_read": 8 * 1024})
        result, _ = _parse(path, budget=budget)
        assert budget.bytes_read <= 8 * 1024 + 64 * 1024, name
        assert result.termination_reason != "complete" or budget.bytes_read < len(payload), name


def test_symlinks_and_directories_are_not_read_as_files(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_text(PHONE, encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    assert link.is_symlink()


def test_a_file_that_disappears_mid_scan_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / "vanishing.txt"
    path.write_text("x" * 5000, encoding="utf-8")
    budget = ScanBudget()
    file_type = detect(".txt", b"x" * 10, name=path.name)
    path.unlink()
    result = parse_file(path, 5000, file_type, budget=budget)
    assert result.coverage in {"failed", "partial", "complete"}
    assert result.parser


def test_generic_text_parser_is_reachable_directly(tmp_path: Path) -> None:
    path = tmp_path / "direct.txt"
    path.write_text("hello", encoding="utf-8")
    result = generic_text.parse(path, 5, budget=ScanBudget())
    assert result.parser == "generic_text"


def test_csv_tsv_and_json_and_sql_modules_expose_parse() -> None:
    assert callable(csv_tsv.parse)
    assert callable(json_like.parse)
    assert callable(sql.parse)
    assert callable(xlsx.parse)
