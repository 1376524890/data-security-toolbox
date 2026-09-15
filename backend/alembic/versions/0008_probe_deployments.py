"""probe deployment plane: deployments, credentials, enrollments, events

Revision ID: 0008_probe_deployments
Revises: 0007_file_md5
Create Date: 2026-09-15
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_probe_deployments"
down_revision = "0007_file_md5"
branch_labels = None
depends_on = None


def _table_exists(name: str) -> bool:
    bind = op.get_bind()
    return name in sa.inspect(bind).get_table_names()


def _column_exists(table: str, name: str) -> bool:
    bind = op.get_bind()
    return any(column["name"] == name for column in sa.inspect(bind).get_columns(table))


def _index_exists(table: str, index: str) -> bool:
    bind = op.get_bind()
    return any(item["name"] == index for item in sa.inspect(bind).get_indexes(table))


def _create_table_if_missing(name: str, *columns: sa.Column) -> None:
    if not _table_exists(name):
        op.create_table(name, *columns)


def _create_index_if_missing(index: str, table: str, *columns: str, **kwargs) -> None:
    if not _index_exists(table, index):
        op.create_index(index, table, list(columns), **kwargs)


def upgrade() -> None:
    _create_table_if_missing(
        "probe_deployments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("username", sa.String(128), nullable=False, server_default="root"),
        sa.Column("auth_type", sa.String(32), nullable=False, server_default="password"),
        sa.Column("profile", sa.String(32), nullable=False, server_default="standard"),
        sa.Column("status", sa.String(32), nullable=False, server_default="CREATED"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_stage", sa.String(255), nullable=False, server_default="queued"),
        sa.Column("error_code", sa.String(64), nullable=False, server_default=""),
        sa.Column("error_message", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(128), nullable=False, server_default=""),
        sa.Column("task_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("package_version", sa.String(64), nullable=False, server_default=""),
        sa.Column("package_digest", sa.String(64), nullable=False, server_default=""),
        sa.Column("backend_url", sa.String(512), nullable=False, server_default=""),
        sa.Column("callback_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("credential_destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("probe_id", sa.Integer(), sa.ForeignKey("probes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("preflight_result", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("result", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    _create_index_if_missing("ix_probe_deployments_host", "probe_deployments", "host")
    _create_index_if_missing("ix_probe_deployments_status", "probe_deployments", "status")
    _create_index_if_missing("ix_probe_deployments_probe_id", "probe_deployments", "probe_id")

    _create_table_if_missing(
        "probe_deployment_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("deployment_id", sa.Integer(), sa.ForeignKey("probe_deployments.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    _create_table_if_missing(
        "probe_enrollments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("deployment_id", sa.Integer(), sa.ForeignKey("probe_deployments.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("probe_id", sa.Integer(), sa.ForeignKey("probes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    _create_table_if_missing(
        "probe_deployment_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("deployment_id", sa.Integer(), sa.ForeignKey("probe_deployments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("stage", sa.String(64), nullable=False, server_default=""),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    _create_index_if_missing("ix_probe_deployment_events_deployment_id", "probe_deployment_events", "deployment_id")

    if not _column_exists("probes", "deployment_id"):
        op.add_column("probes", sa.Column("deployment_id", sa.Integer(), sa.ForeignKey("probe_deployments.id", ondelete="SET NULL"), nullable=True))
        _create_index_if_missing("ix_probes_deployment_id", "probes", "deployment_id")


def downgrade() -> None:
    if _column_exists("probes", "deployment_id"):
        op.drop_index("ix_probes_deployment_id", table_name="probes")
        op.drop_column("probes", "deployment_id")
    for table in ("probe_deployment_events", "probe_enrollments", "probe_deployment_credentials", "probe_deployments"):
        if _table_exists(table):
            op.drop_table(table)
