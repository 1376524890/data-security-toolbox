"""alert lifecycle: non-unique fingerprint, correlation key, delivery retry

Revision ID: 0006_alert_lifecycle
Revises: 0005_v3_continuous
Create Date: 2026-09-03
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_alert_lifecycle"
down_revision = "0005_v3_continuous"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    columns = _columns("alerts")
    if "correlation_key" not in columns:
        op.add_column("alerts", sa.Column("correlation_key", sa.String(64), nullable=False, server_default=""))
    if "alert_instance" not in columns:
        op.add_column("alerts", sa.Column("alert_instance", sa.Integer(), nullable=False, server_default="1"))

    # Ensure alerts.fingerprint is a plain (non-unique) index so resolved alerts
    # never swallow a future recurrence. The current ORM model already creates a
    # non-unique index, so we only rebuild when a legacy unique index exists.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    indexes = {item["name"]: item for item in inspector.get_indexes("alerts")}
    if "ix_alerts_fingerprint" in indexes and indexes["ix_alerts_fingerprint"].get("unique"):
        op.drop_index("ix_alerts_fingerprint", table_name="alerts")
        op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])
    elif "ix_alerts_fingerprint" not in indexes:
        op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])

    delivery_columns = _columns("alert_deliveries")
    if "max_attempts" not in delivery_columns:
        op.add_column("alert_deliveries", sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"))
    if "next_attempt_at" not in delivery_columns:
        op.add_column("alert_deliveries", sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_index("ix_alerts_fingerprint", table_name="alerts")
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"], unique=True)
    op.drop_column("alert_deliveries", "next_attempt_at")
    op.drop_column("alert_deliveries", "max_attempts")
    op.drop_column("alerts", "alert_instance")
    op.drop_column("alerts", "correlation_key")
