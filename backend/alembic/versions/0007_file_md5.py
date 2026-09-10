"""file records: persist md5 alongside sha256

Revision ID: 0007_file_md5
Revises: 0006_alert_lifecycle
Create Date: 2026-09-04
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_file_md5"
down_revision = "0006_alert_lifecycle"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    columns = _columns("files")
    if "md5" not in columns:
        op.add_column("files", sa.Column("md5", sa.String(64), nullable=False, server_default=""))
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes("files")}
    if "ix_files_md5" not in indexes:
        op.create_index("ix_files_md5", "files", ["md5"])


def downgrade() -> None:
    op.drop_column("files", "md5")
