import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


def test_deployment_migration_creates_indexes_and_is_repeatable():
    path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0008_probe_deployments.py"
    spec = importlib.util.spec_from_file_location("deployment_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        # SQLite cannot ALTER ADD a foreign key; exercise the already-present
        # probe column path here. PostgreSQL upgrade is verified during rollout.
        connection.execute(sa.text("CREATE TABLE probes (id INTEGER PRIMARY KEY, deployment_id INTEGER)"))
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        migration.upgrade()
        inspector = sa.inspect(connection)
        indexes = {row["name"]: row["column_names"] for row in inspector.get_indexes("probe_deployments")}
        assert indexes["ix_probe_deployments_host"] == ["host"]
        assert indexes["ix_probe_deployments_status"] == ["status"]
        assert indexes["ix_probe_deployments_probe_id"] == ["probe_id"]
        assert "probe_enrollments" in inspector.get_table_names()


def test_probe_removal_migration_is_repeatable_and_reversible():
    """The removal columns are added to a live table, so re-running is safe.

    Deployments already in the database predate the removal feature and are all
    push deployments, so the column has to arrive with a default that says so
    rather than leaving existing rows unclassified.
    """
    path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0014_probe_removal.py"
    spec = importlib.util.spec_from_file_location("probe_removal_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(sa.text(
            "CREATE TABLE probe_deployments (id INTEGER PRIMARY KEY, host VARCHAR(255), name VARCHAR(128))"
        ))
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        migration.upgrade()
        inspector = sa.inspect(connection)
        columns = {row["name"]: row for row in inspector.get_columns("probe_deployments")}
        assert {"action", "removal_options"} <= set(columns)
        assert "install" in str(columns["action"]["default"])
        assert "ix_probe_deployments_action" in {row["name"] for row in inspector.get_indexes("probe_deployments")}
        migration.downgrade()
        remaining = {row["name"] for row in sa.inspect(connection).get_columns("probe_deployments")}
        assert "action" not in remaining and "removal_options" not in remaining
