"""Probe-side data asset discovery (no network access required)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

from probe import data_assets  # noqa: E402
from shared.scanning import magic  # noqa: E402
from shared.scanning.budget import ScanBudget  # noqa: E402
from shared.scanning.parsers import parse_file  # noqa: E402

# --- configured scope: exclusions and file-type allow-list -------------------

def _write_scope_tree(root: Path) -> None:
    (root / "keep").mkdir(parents=True, exist_ok=True)
    (root / "skipme").mkdir(parents=True, exist_ok=True)
    (root / "skipme2").mkdir(parents=True, exist_ok=True)
    (root / "nested" / "archive").mkdir(parents=True, exist_ok=True)
    (root / "keep" / "customers.csv").write_text(
        "id,name,phone\n1,张三,13800138000\n", encoding="utf-8"
    )
    (root / "keep" / "notes.txt").write_text("phone 13800138000\n", encoding="utf-8")
    (root / "skipme" / "excluded.csv").write_text(
        "id,name,phone\n9,李四,13900139000\n", encoding="utf-8"
    )
    (root / "skipme2" / "sibling.csv").write_text(
        "id,name,phone\n8,王五,13700137000\n", encoding="utf-8"
    )
    (root / "nested" / "archive" / "dep.csv").write_text(
        "id,name,phone\n7,赵六,13600136000\n", encoding="utf-8"
    )


def test_exclude_paths_removes_exactly_the_configured_subtree(tmp_path: Path) -> None:
    """A prefix exclusion must not swallow a sibling that merely shares its text."""
    _write_scope_tree(tmp_path)
    report = data_assets.discover_data_assets({
        "paths": [str(tmp_path)], "max_files": 50, "max_depth": 4,
        "include_databases": False,
        # A directory exclusion prunes the subtree; a file exclusion loses one file.
        "exclude_paths": [str(tmp_path / "skipme"), str(tmp_path / "keep" / "notes.txt")],
    })
    names = {item["name"] for item in report["assets"]}
    assert "excluded.csv" not in names
    assert "sibling.csv" in names          # /skipme2 is a different subtree
    assert "customers.csv" in names
    assert "notes.txt" not in names
    assert report["complete"] is True
    scope = report["coverage"]["scope_filter"]
    assert scope["excluded_directories"] == 1
    assert scope["excluded_files"] == 1
    assert str(tmp_path / "skipme") in scope["exclude_paths"]


def test_exclude_paths_accepts_a_bare_directory_name(tmp_path: Path) -> None:
    """A name without a separator filters that directory wherever it appears."""
    _write_scope_tree(tmp_path)
    report = data_assets.discover_data_assets({
        "paths": [str(tmp_path)], "max_files": 50, "max_depth": 4,
        "include_databases": False, "exclude_paths": ["archive"],
    })
    names = {item["name"] for item in report["assets"]}
    assert "dep.csv" not in names
    assert "customers.csv" in names
    assert report["coverage"]["scope_filter"]["excluded_directories"] >= 1


def test_file_types_is_an_allow_list_that_is_reported_not_hidden(tmp_path: Path) -> None:
    """Filtered-by-type is counted separately from skipped or truncated."""
    _write_scope_tree(tmp_path)
    report = data_assets.discover_data_assets({
        "paths": [str(tmp_path)], "max_files": 50, "max_depth": 4,
        "include_databases": False, "file_types": [".csv"],
    })
    names = {item["name"] for item in report["assets"]}
    assert "customers.csv" in names
    assert "notes.txt" not in names
    assert report["coverage"]["scope_filter"]["files_filtered_by_type"] >= 1
    # Filtering by type is scope, not a budget stop: the run is still complete.
    assert report["complete"] is True
    assert report["coverage"]["termination_reason"] == "complete"


def test_no_scope_configuration_reports_no_filter_evidence(tmp_path: Path) -> None:
    """Absent excludes must not add an empty, misleading scope block."""
    _write_scope_tree(tmp_path)
    report = data_assets.discover_data_assets({
        "paths": [str(tmp_path)], "max_files": 50, "max_depth": 4, "include_databases": False,
    })
    assert "scope_filter" not in report["coverage"]


def test_scope_filter_parses_toml_style_list_and_string() -> None:
    from_list = data_assets.scope_filter_for({"exclude_paths": ["/a/b", "node_modules"],
                                              "file_types": ["csv", ".TXT"]})
    assert from_list.excludes_path("/a/b/c.csv") is True
    assert from_list.excludes_path("/a/bc/c.csv") is False
    assert from_list.excludes_directory("node_modules", "/x/node_modules") is True
    assert from_list.allows_file("x.csv") is True
    assert from_list.allows_file("x.txt") is True
    assert from_list.allows_file("x.md") is False
    from_string = data_assets.scope_filter_for({"exclude_paths": "/tmp/only", "file_types": "csv,tsv"})
    assert from_string.excludes_path("/tmp/only/a") is True
    assert from_string.allows_file("a.tsv") is True
    assert from_string.allows_file("a.json") is False


def _write_sample_tree(root: Path) -> None:
    (root / "customer_data").mkdir(parents=True, exist_ok=True)
    (root / "customers.csv").write_text(
        "id,name,phone,id_card,email\n"
        "1,张三,13800138000,110101199003077518,zhangsan@example.com\n",
        encoding="utf-8",
    )
    (root / "secrets.txt").write_text("api_key=sk-abcdefghijklmnopqrstuvwxyz0123456789\n", encoding="utf-8")
    (root / "app.db").write_bytes(b"SQLite format 3\x00" + bytes(32))
    (root / "customer_data" / "dump.sql").write_text(
        "CREATE TABLE customer (id int, phone varchar(20), id_card varchar(18));\n", encoding="utf-8"
    )
    (root / "binary.png").write_bytes(bytes(range(256)) * 4)


def test_discover_data_assets_classifies_files_and_columns(tmp_path: Path) -> None:
    _write_sample_tree(tmp_path)
    report = data_assets.discover_data_assets(
        {"paths": [str(tmp_path)], "max_files": 50, "max_depth": 3, "include_databases": False}
    )
    assert report["complete"] is True
    assert report["error"] == ""
    by_name = {item["name"]: item for item in report["assets"]}

    csv_asset = by_name["customers.csv"]
    assert csv_asset["asset_type"] == "table"
    assert csv_asset["sensitivity"] == "High"
    assert {"phone", "id_card"} <= set(csv_asset["categories"])
    assert {column["name"] for column in csv_asset["columns"]} >= {"phone", "id_card", "email"}
    assert csv_asset["sha256"]  # identity is reported for small files

    secrets = by_name["secrets.txt"]
    assert secrets["sensitivity"] == "Critical"
    assert "api_key" in secrets["categories"]
    # Raw matched values must never leave the host.
    assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in repr(report)

    assert by_name["app.db"]["asset_type"] == "database"
    assert by_name["dump.sql"]["asset_type"] == "database"
    assert any(item["asset_type"] == "directory" for item in report["assets"])


def test_discover_data_assets_requires_configured_paths(tmp_path: Path) -> None:
    report = data_assets.discover_data_assets({"paths": [], "include_databases": False})
    # An authoritative empty report would mark every known asset as gone.
    assert report["complete"] is False
    assert report["error"]
    assert report["assets"] == []


def test_discover_data_assets_respects_max_files(tmp_path: Path) -> None:
    _write_sample_tree(tmp_path)
    report = data_assets.discover_data_assets(
        {"paths": [str(tmp_path)], "max_files": 1, "max_depth": 2, "include_databases": False}
    )
    assert len([item for item in report["assets"] if item["asset_type"] != "directory"]) == 1
    assert report["complete"] is False


def _columns_of(path) -> list[dict]:
    """Column inference through the current parser path (shared scanning stage 3)."""
    budget = ScanBudget()
    file_type = magic.detect(path.suffix.lower(), magic.probe_head(path), name=path.name)
    result = parse_file(path, path.stat().st_size, file_type, budget=budget)
    columns, _, _ = data_assets._columns_from_result(result, path.name)
    return columns


def test_columns_are_inferred_from_json_and_sql(tmp_path) -> None:
    json_file = tmp_path / 'records.json'
    json_file.write_text('{"phone": "13800138000", "user_id": 3}', encoding='utf-8')
    columns = _columns_of(json_file)
    assert {column['name'] for column in columns} == {'phone', 'user_id'}
    assert any('phone' in column['categories'] for column in columns)

    sql_file = tmp_path / 'schema.sql'
    sql_file.write_text("CREATE TABLE t (id int, id_card varchar(18));", encoding='utf-8')
    columns = _columns_of(sql_file)
    assert {column['name'] for column in columns} == {'id', 'id_card'}
    assert any('id_card' in column['categories'] for column in columns)


def test_formats_and_missing_directory(tmp_path):
    import gzip
    (tmp_path / 'users.tsv').write_text('name\tphone\n张三\t13800138000', encoding='utf-8')
    (tmp_path / 'users.jsonl').write_text('{"phone":"13800138000"}\n{"phone":"13900139000"}', encoding='utf-8')
    with gzip.open(tmp_path / 'dump.sql.gz', 'wt') as output:
        output.write('CREATE TABLE users (phone varchar(20));')
    report = data_assets.discover_data_assets({'paths': [str(tmp_path)], 'include_databases': False})
    for item in report['assets']:
        if item['asset_type'] != 'directory':
            assert 'phone' in {column['name'] for column in item['columns']}
    missing = data_assets.discover_data_assets({'paths': [str(tmp_path / 'missing')], 'include_databases': False})
    assert not missing['complete'] and missing['error']


def test_cancelled_walk_and_overlapping_roots(tmp_path):
    import threading
    _write_sample_tree(tmp_path)
    stop = threading.Event()
    stop.set()
    assert not data_assets.discover_data_assets({'paths': [str(tmp_path)]}, stop)['complete']
    report = data_assets.discover_data_assets({'paths': [str(tmp_path), str(tmp_path / 'customer_data')], 'include_databases': False})
    paths = [item['path'] for item in report['assets'] if item['asset_type'] != 'directory']
    assert len(paths) == len(set(paths))


def test_symlink_not_followed(tmp_path):
    target = tmp_path / 'target.csv'
    target.write_text('phone\n13800138000')
    link = tmp_path / 'link.csv'
    link.symlink_to(target)
    assert data_assets.inspect_file(link, ScanBudget()) is None
