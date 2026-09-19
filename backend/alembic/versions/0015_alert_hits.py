"""Alert hit log and the detection sample-size ceiling.

Revision ID: 0015_alert_hits
Revises: 0014_probe_removal
Create Date: 2026-09-19

Additive only and guarded, so a re-run or a database already created by
``Base.metadata.create_all`` is safe. Two independent gaps are closed:

* suppression collapses repeat hits into a single live Alert, so ``alert_hits``
  preserves each observation (first / latest / highest-risk) instead of only the
  first finding;
* ``detections.sample_limit`` keeps the configured sample ceiling next to the
  actual ``sample_size``, so an under-sampled file is not reported as a
  full-size sample.
"""
from alembic import op
import sqlalchemy as sa

revision = "0015_alert_hits"
down_revision = "0014_probe_removal"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("alert_hits"):
        _create_alert_hits()
    detection_columns = {column["name"] for column in inspector.get_columns("detections")}
    if "sample_limit" not in detection_columns:
        op.add_column("detections", sa.Column("sample_limit", sa.Integer(), nullable=False, server_default="0"))


def _create_alert_hits() -> None:
    op.create_table(
        "alert_hits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("detection_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("probe_id", sa.Integer(), sa.ForeignKey("probes.id"), nullable=True),
        sa.Column("source", sa.String(128), nullable=False, server_default=""),
        sa.Column("asset", sa.String(255), nullable=False, server_default=""),
        sa.Column("ioc", sa.String(512), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default=""),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("is_first", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_latest", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_highest_risk", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("alert_id", "finding_id", name="uq_alert_hit_finding"),
    )
    op.create_index("ix_alert_hits_alert_id", "alert_hits", ["alert_id"])
    op.create_index("ix_alert_hits_finding_id", "alert_hits", ["finding_id"])
    op.create_index("ix_alert_hits_probe_id", "alert_hits", ["probe_id"])
    op.create_index("ix_alert_hits_asset", "alert_hits", ["asset"])
    op.create_index("ix_alert_hits_observed_at", "alert_hits", ["observed_at"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("alert_hits"):
        for name in (
            "ix_alert_hits_observed_at",
            "ix_alert_hits_asset",
            "ix_alert_hits_probe_id",
            "ix_alert_hits_finding_id",
            "ix_alert_hits_alert_id",
        ):
            op.drop_index(name, table_name="alert_hits")
        op.drop_table("alert_hits")
    if inspector.has_table("detections"):
        columns = {column["name"] for column in inspector.get_columns("detections")}
        if "sample_limit" in columns:
            op.drop_column("detections", "sample_limit")
