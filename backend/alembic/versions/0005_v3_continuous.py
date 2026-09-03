"""v3 continuous detection and alerting

Revision ID: 0005_v3_continuous
Revises: 0004_enterprise_platform
Create Date: 2026-09-03
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_v3_continuous"
down_revision = "0004_enterprise_platform"
branch_labels = None
depends_on = None


def _add(table: str, name: str, column: sa.Column) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns(table)}
    if name not in columns:
        op.add_column(table, column)


def upgrade() -> None:
    _add("users", "password_hash", sa.Column("password_hash", sa.String(512), nullable=False, server_default=""))
    op.create_table(
        "admin_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    _add("probes", "token_hash", sa.Column("token_hash", sa.String(64), nullable=False, server_default=""))
    _add("pcaps", "segment_id", sa.Column("segment_id", sa.String(128), nullable=False, server_default="", index=True))
    _add("pcaps", "sequence", sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"))
    _add("pcaps", "capture_interface", sa.Column("capture_interface", sa.String(128), nullable=False, server_default=""))
    _add("pcaps", "capture_started_at", sa.Column("capture_started_at", sa.String(64), nullable=False, server_default=""))
    _add("pcaps", "capture_finished_at", sa.Column("capture_finished_at", sa.String(64), nullable=False, server_default=""))
    _add("pcaps", "ingest_status", sa.Column("ingest_status", sa.String(32), nullable=False, server_default="pending"))
    _add("pcaps", "analysis_status", sa.Column("analysis_status", sa.String(32), nullable=False, server_default="pending"))
    _add("pcaps", "probe_metadata", sa.Column("probe_metadata", sa.JSON(), nullable=False, server_default="{}"))
    _add("pcaps", "total_packet_count", sa.Column("total_packet_count", sa.Integer(), nullable=False, server_default="0"))
    _add("pcaps", "indexed_packet_count", sa.Column("indexed_packet_count", sa.Integer(), nullable=False, server_default="0"))
    _add("pcaps", "file_type", sa.Column("file_type", sa.String(64), nullable=False, server_default=""))
    _add("pcaps", "retention_status", sa.Column("retention_status", sa.String(32), nullable=False, server_default="active"))
    op.create_index("uq_pcap_probe_segment", "pcaps", ["probe_id", "segment_id"], unique=True)

    _add("incidents", "fingerprint", sa.Column("fingerprint", sa.String(64), nullable=False, server_default="", index=True))
    _add("incidents", "probe_id", sa.Column("probe_id", sa.Integer(), sa.ForeignKey("probes.id"), nullable=True))
    _add("incidents", "source", sa.Column("source", sa.String(128), nullable=False, server_default="pipeline"))
    _add("incidents", "last_seen", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    _add("incidents", "occurrence_count", sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"))

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("detection_findings.id"), nullable=True, index=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=True, index=True),
        sa.Column("probe_id", sa.Integer(), sa.ForeignKey("probes.id"), nullable=True, index=True),
        sa.Column("severity", sa.String(16), nullable=False, index=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("title", sa.String(255), nullable=False, index=True),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="new", index=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source", sa.String(128), nullable=False, server_default="pipeline", index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id"), nullable=False, index=True),
        sa.Column("channel", sa.String(32), nullable=False, index=True),
        sa.Column("target", sa.String(512), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending", index=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("alert_deliveries")
    op.drop_table("alerts")
    op.drop_column("incidents", "occurrence_count")
    op.drop_column("incidents", "last_seen")
    op.drop_column("incidents", "source")
    op.drop_column("incidents", "probe_id")
    op.drop_column("incidents", "fingerprint")
    op.drop_index("uq_pcap_probe_segment", table_name="pcaps")
    for name in ["retention_status", "file_type", "indexed_packet_count", "total_packet_count", "probe_metadata", "analysis_status", "ingest_status", "capture_finished_at", "capture_started_at", "capture_interface", "sequence", "segment_id"]:
        op.drop_column("pcaps", name)
    op.drop_column("probes", "token_hash")
    op.drop_table("admin_sessions")
    op.drop_column("users", "password_hash")
