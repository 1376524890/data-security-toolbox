"""probe deployment data-asset collection settings

Revision ID: 0009_probe_data_assets
Revises: 0008_probe_deployments
Create Date: 2026-09-15
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_probe_data_assets"
down_revision = "0008_probe_deployments"
branch_labels = None
depends_on = None


def _column_exists(table: str, name: str) -> bool:
    bind = op.get_bind()
    return any(column["name"] == name for column in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    if not _column_exists("probe_deployments", "data_config"):
        op.add_column(
            "probe_deployments",
            sa.Column("data_config", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )


def downgrade() -> None:
    if _column_exists("probe_deployments", "data_config"):
        op.drop_column("probe_deployments", "data_config")
