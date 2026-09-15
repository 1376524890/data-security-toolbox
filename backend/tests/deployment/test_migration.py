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
