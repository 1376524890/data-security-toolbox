"""Probe removal: reuse probe_deployments for the uninstall action.

Revision ID: 0014_probe_removal
Revises: 0013_safe_json_evidence
Create Date: 2026-09-17

Additive only, and guarded so a re-run is safe. A removal is the same SSH push
with the same credential, event and status machinery as a deployment, so it
needs no new table: ``action`` distinguishes the two and ``removal_options``
records what the operator asked to delete on the host.
"""
from alembic import op
import sqlalchemy as sa

revision = "0014_probe_removal"
down_revision = "0013_safe_json_evidence"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _indexes(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return set()
    return {index["name"] for index in inspector.get_indexes(table)}


def upgrade() -> None:
    columns = _columns("probe_deployments")
    if not columns:
        return
    if "action" not in columns:
        # Existing rows are all push deployments.
        op.add_column(
            "probe_deployments",
            sa.Column("action", sa.String(16), nullable=False, server_default="install"),
        )
    if "removal_options" not in columns:
        op.add_column(
            "probe_deployments",
            sa.Column("removal_options", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )
    if "ix_probe_deployments_action" not in _indexes("probe_deployments"):
        op.create_index("ix_probe_deployments_action", "probe_deployments", ["action"])


def downgrade() -> None:
    columns = _columns("probe_deployments")
    if "ix_probe_deployments_action" in _indexes("probe_deployments"):
        op.drop_index("ix_probe_deployments_action", table_name="probe_deployments")
    if "removal_options" in columns:
        op.drop_column("probe_deployments", "removal_options")
    if "action" in columns:
        op.drop_column("probe_deployments", "action")
