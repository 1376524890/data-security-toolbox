"""Migration 0010 must work on a live deployment *and* be re-runnable.

`0001_initial` runs `Base.metadata.create_all`, so a fresh database already has
these tables and 0010 has to no-op. An existing deployment is at 0009 and has
none of them, so 0010 is the only creator - and there the two tables reference
each other, which PostgreSQL refuses when the key is emitted inline in the
`CREATE TABLE`. Both paths are exercised here.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"
MIGRATION_PATH = VERSIONS / "0010_rule_sets.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("ruleset_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sandbox(connection) -> None:
    """Recreate the tables 0009 leaves behind for the two referenced models."""
    connection.execute(sa.text("CREATE TABLE probes (id INTEGER PRIMARY KEY)"))


def test_migration_is_repeatable_and_creates_all_three_tables() -> None:
    migration = _load_migration()
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        _sandbox(connection)
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        tables = set(sa.inspect(connection).get_table_names())
        assert {"rule_sets", "rules", "rule_set_versions"} <= tables

        # Running it again must not raise: a fresh database reaches 0010 with the
        # tables already present from `create_all`.
        connection.execute(sa.text("DROP TABLE rules"))
        connection.execute(sa.text("DROP TABLE rule_set_versions"))
        connection.execute(sa.text("DROP TABLE rule_sets"))
        migration.upgrade()
        tables = set(sa.inspect(connection).get_table_names())
        assert {"rule_sets", "rules", "rule_set_versions"} <= tables


def test_rule_sets_never_declares_an_inline_forward_key() -> None:
    """The exact bug this migration had: a CREATE TABLE referencing a later table."""
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    block = source.split('op.create_table(\n            "rule_sets"')[1].split(")\n")[0]
    assert "rule_set_versions" not in block, (
        "rule_sets must be created without a foreign key to rule_set_versions: "
        "PostgreSQL rejects a CREATE TABLE whose referenced table does not exist yet"
    )
    # The key still has to exist in the end, added once both tables are present.
    assert "create_foreign_key" in source
    assert source.index('"rule_set_versions",') < source.index("create_foreign_key")


def test_downgrade_drops_the_key_before_the_table_it_points_at() -> None:
    migration = _load_migration()
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    downgrade_body = source.split("def downgrade() -> None:")[1]
    assert downgrade_body.index("drop_constraint") < downgrade_body.index('op.drop_table("rule_set_versions")')


def test_the_migration_only_adds_tables() -> None:
    """An upgrade must never drop or truncate anything that already exists."""
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    upgrade_body = source.split("def upgrade() -> None:")[1].split("def downgrade()")[0]
    for destructive in ("drop_table", "drop_column", "delete(", "TRUNCATE"):
        assert destructive not in upgrade_body, destructive
