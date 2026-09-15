"""Probe-side data asset discovery (no network access required)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

from probe import data_assets  # noqa: E402


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


def test_infer_columns_from_json_and_sql() -> None:
    json_columns = data_assets.infer_columns('{"phone": "13800138000", "user_id": 3}', ".json")
    assert {column["name"] for column in json_columns} == {"phone", "user_id"}
    assert any("phone" in column["categories"] for column in json_columns)

    sql_columns = data_assets.infer_columns("CREATE TABLE t (id int, id_card varchar(18));", ".sql")
    assert {column["name"] for column in sql_columns} == {"id", "id_card"}


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
    assert data_assets.inspect_file(link) is None
