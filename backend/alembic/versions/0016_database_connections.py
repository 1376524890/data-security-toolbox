"""Target database connections and source-aware instance identity.

Revision ID: 0016_database_connections
Revises: 0015_alert_hits
Create Date: 2026-09-20

Additive and guarded, so re-running it (or running it against a schema produced
by ``Base.metadata.create_all``) is safe. Two changes:

* ``database_connections`` stores a target database the worker may read. The
  password lives AES-GCM encrypted (ciphertext/nonce/key id), never in the clear;
* an instance's identity becomes ``(owner_key, path)``. ``owner_key`` is
  ``probe:<id>`` for files and ``db:<connection_id>`` for a database table, so a
  database-sourced row never has to borrow a ``probe_id`` it does not have.
"""
from alembic import op
import sqlalchemy as sa

revision = "0016_database_connections"
down_revision = "0015_alert_hits"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("database_connections"):
        _create_connections()
    _add_column("asset_instances", "owner_key",
                sa.Column("owner_key", sa.String(160), nullable=False, server_default=""))
    _add_column("asset_instances", "source_kind",
                sa.Column("source_kind", sa.String(16), nullable=False, server_default="file"))
    _add_column("detections", "source_kind",
                sa.Column("source_kind", sa.String(16), nullable=False, server_default="file"))
    # Existing rows are files owned by their probe; nothing is invented for them.
    op.execute(
        "UPDATE asset_instances SET owner_key = 'probe:' || probe_id "
        "WHERE (owner_key IS NULL OR owner_key = '') AND probe_id IS NOT NULL"
    )
    if _column_nullable("asset_instances", "probe_id"):
        pass
    else:
        with op.batch_alter_table("asset_instances") as batch:
            batch.alter_column("probe_id", existing_type=sa.Integer(), nullable=True)
    if _column_nullable("detections", "probe_id"):
        pass
    else:
        with op.batch_alter_table("detections") as batch:
            batch.alter_column("probe_id", existing_type=sa.Integer(), nullable=True)
    _replace_unique("asset_instances", "uq_asset_instance_probe_path",
                    "uq_asset_instance_owner_path", ["owner_key", "path"])
    _create_index("ix_asset_instances_owner_key", "asset_instances", ["owner_key"])
    _create_index("ix_asset_instances_source_kind", "asset_instances", ["source_kind"])
    _create_index("ix_detections_source_kind", "detections", ["source_kind"])


def downgrade() -> None:
    """Drop the database-connection feature.

    Destructive by nature: the connections and their encrypted passwords are
    removed. Instance rows are left in place (they are observations, not
    configuration) and only the new columns disappear.
    """
    _replace_unique("asset_instances", "uq_asset_instance_owner_path",
                    "uq_asset_instance_probe_path", ["probe_id", "path"])
    _drop_column("asset_instances", "owner_key")
    _drop_column("asset_instances", "source_kind")
    _drop_column("detections", "source_kind")
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("database_connections"):
        op.drop_table("database_connections")


def _create_connections() -> None:
    op.create_table(
        "database_connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, server_default=""),
        sa.Column("engine", sa.String(32), nullable=False, server_default=""),
        sa.Column("host", sa.String(255), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("database", sa.String(128), nullable=False, server_default=""),
        sa.Column("username", sa.String(128), nullable=False, server_default=""),
        sa.Column("password_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("password_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("password_key_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("tls_mode", sa.String(16), nullable=False, server_default=""),
        sa.Column("options", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_status", sa.String(32), nullable=False, server_default="untested"),
        sa.Column("last_test_error", sa.Text(), nullable=False, server_default=""),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extra", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("name", name="uq_database_connection_name"),
    )
    op.create_index("ix_database_connections_name", "database_connections", ["name"])
    op.create_index("ix_database_connections_engine", "database_connections", ["engine"])


def _add_column(table: str, name: str, column: sa.Column) -> None:
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(table)}
    if name not in columns:
        op.add_column(table, column)


def _drop_column(table: str, name: str) -> None:
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns(table)}
    if name in columns:
        with op.batch_alter_table(table) as batch:
            batch.drop_column(name)


def _column_nullable(table: str, name: str) -> bool:
    for column in sa.inspect(op.get_bind()).get_columns(table):
        if column["name"] == name:
            return bool(column["nullable"])
    return True


def _create_index(name: str, table: str, columns: list[str]) -> None:
    existing = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes(table)}
    if name not in existing:
        op.create_index(name, table, columns)


def _replace_unique(table: str, old: str, new: str, columns: list[str]) -> None:
    """Swap one unique constraint for another, tolerating either state."""
    inspector = sa.inspect(op.get_bind())
    names = {item["name"] for item in inspector.get_unique_constraints(table)}
    names |= {item["name"] for item in inspector.get_indexes(table) if item.get("unique")}
    if old in names:
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(old, type_="unique")
    if new not in names:
        with op.batch_alter_table(table) as batch:
            batch.create_unique_constraint(new, columns)
