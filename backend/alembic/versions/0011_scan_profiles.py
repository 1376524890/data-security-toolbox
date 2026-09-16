"""versioned scan profiles

Revision ID: 0011_scan_profiles
Revises: 0010_rule_sets
Create Date: 2026-09-16

Additive only. The server defaults match the shipped scanner defaults, so an
existing deployment that never creates a profile behaves exactly as before.
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_scan_profiles"
down_revision = "0010_rule_sets"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if _has_table("scan_profiles"):
        return
    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("include_paths", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("exclude_paths", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("file_types", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("max_files", sa.Integer(), nullable=False, server_default="200"),
        sa.Column("max_dirs", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("max_depth", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("max_runtime_seconds", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("max_bytes_read", sa.BigInteger(), nullable=False, server_default="536870912"),
        sa.Column("max_single_file_size", sa.BigInteger(), nullable=False, server_default="2097152"),
        sa.Column("max_full_hash_size", sa.BigInteger(), nullable=False, server_default="8388608"),
        sa.Column("large_file_sampling", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sample_block_size", sa.Integer(), nullable=False, server_default="65536"),
        sa.Column("max_sample_rows", sa.Integer(), nullable=False, server_default="25"),
        sa.Column("max_cpu_seconds", sa.Float(), nullable=False, server_default="0"),
        sa.Column("max_rss_mb", sa.Float(), nullable=False, server_default="0"),
        sa.Column("xlsx_max_entries", sa.Integer(), nullable=False, server_default="512"),
        sa.Column("xlsx_max_uncompressed_bytes", sa.BigInteger(), nullable=False,
                  server_default="67108864"),
        sa.Column("xlsx_max_compression_ratio", sa.Float(), nullable=False, server_default="200"),
        sa.Column("xlsx_max_shared_strings", sa.Integer(), nullable=False, server_default="200000"),
        sa.Column("xlsx_max_sheets", sa.Integer(), nullable=False, server_default="32"),
        sa.Column("xlsx_max_columns", sa.Integer(), nullable=False, server_default="256"),
        sa.Column("xlsx_max_rows", sa.Integer(), nullable=False, server_default="200"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scheduled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("created_by", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("name", "version", name="uq_scan_profile_version"),
    )
    op.create_index("ix_scan_profiles_name", "scan_profiles", ["name"])


def downgrade() -> None:
    if _has_table("scan_profiles"):
        op.drop_table("scan_profiles")
