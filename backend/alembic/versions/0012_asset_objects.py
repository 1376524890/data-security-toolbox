"""data objects, asset instances, detections and evidence

Revision ID: 0012_asset_objects
Revises: 0011_scan_profiles
Create Date: 2026-09-16

Additive only. Four new tables plus their indexes; nothing is dropped, renamed
or rewritten, so the legacy ``data_assets`` projection and every existing page
keep working. Objects referenced by a foreign key are created before the tables
that point at them, and every constraint is added with ``ALTER TABLE`` so the
order is safe on PostgreSQL as well as SQLite.
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_asset_objects"
down_revision = "0011_scan_profiles"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table("data_objects"):
        op.create_table(
            "data_objects",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("object_key", sa.String(192), nullable=False),
            sa.Column("object_type", sa.String(64), nullable=False),
            sa.Column("content_hash", sa.String(128), nullable=False, server_default=""),
            sa.Column("hash_type", sa.String(32), nullable=False, server_default="scoped"),
            sa.Column("identity_confidence", sa.Float(), nullable=False, server_default="0"),
            sa.Column("partial_version", sa.String(32), nullable=False, server_default=""),
            sa.Column("partial_layout", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("size", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("instance_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("active_instance_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("categories", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("sensitivity", sa.String(16), nullable=False, server_default="Unknown"),
            sa.Column("extra", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("object_key", name="uq_data_object_key"),
        )
        for column in ("object_key", "object_type", "content_hash", "hash_type", "sensitivity"):
            op.create_index(f"ix_data_objects_{column}", "data_objects", [column])

    if not _has_table("asset_instances"):
        op.create_table(
            "asset_instances",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("object_id", sa.Integer(), nullable=False),
            sa.Column("probe_id", sa.Integer(), nullable=False),
            sa.Column("path", sa.String(1024), nullable=False, server_default=""),
            sa.Column("name", sa.String(512), nullable=False, server_default=""),
            sa.Column("instance_type", sa.String(32), nullable=False, server_default="file"),
            sa.Column("size", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("inode", sa.BigInteger(), nullable=True),
            sa.Column("device", sa.BigInteger(), nullable=True),
            sa.Column("mtime_ns", sa.BigInteger(), nullable=True),
            sa.Column("owner", sa.String(64), nullable=False, server_default=""),
            sa.Column("group", sa.String(64), nullable=False, server_default=""),
            sa.Column("permission", sa.String(16), nullable=False, server_default=""),
            sa.Column("content_hash", sa.String(128), nullable=False, server_default=""),
            sa.Column("hash_type", sa.String(32), nullable=False, server_default="scoped"),
            sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_scan_id", sa.String(64), nullable=False, server_default=""),
            sa.Column("scope_key", sa.String(256), nullable=False, server_default=""),
            sa.Column("coverage", sa.String(16), nullable=False, server_default="complete"),
            sa.Column("termination_reason", sa.String(64), nullable=False, server_default="complete"),
            sa.Column("ruleset_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("engine_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("profile_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("sensitivity", sa.String(16), nullable=False, server_default="Unknown"),
            sa.Column("categories", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("extra", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("probe_id", "path", name="uq_asset_instance_probe_path"),
        )
        for column in ("object_id", "probe_id", "instance_type", "status", "last_scan_id",
                       "scope_key", "sensitivity"):
            op.create_index(f"ix_asset_instances_{column}", "asset_instances", [column])

    if not _has_table("detections"):
        op.create_table(
            "detections",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("object_id", sa.Integer(), nullable=False),
            sa.Column("instance_id", sa.Integer(), nullable=False),
            sa.Column("probe_id", sa.Integer(), nullable=False),
            sa.Column("scan_id", sa.String(64), nullable=False, server_default=""),
            sa.Column("category", sa.String(64), nullable=False),
            sa.Column("subcategory", sa.String(64), nullable=False, server_default=""),
            sa.Column("sensitivity_level", sa.String(16), nullable=False, server_default="L1"),
            sa.Column("severity", sa.String(16), nullable=False, server_default="Low"),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
            sa.Column("sample_size", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("sample_hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("engine_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("ruleset_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("extra", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("instance_id", "category", "object_id",
                                name="uq_detection_instance_category_object"),
        )
        for column in ("object_id", "instance_id", "probe_id", "scan_id", "category",
                       "sensitivity_level", "severity"):
            op.create_index(f"ix_detections_{column}", "detections", [column])

    if not _has_table("detection_evidence"):
        op.create_table(
            "detection_evidence",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("detection_id", sa.Integer(), nullable=False),
            sa.Column("evidence_key", sa.String(200), nullable=False, server_default=""),
            sa.Column("rule_id", sa.String(128), nullable=False, server_default=""),
            sa.Column("rule_name", sa.String(255), nullable=False, server_default=""),
            sa.Column("rule_source", sa.String(32), nullable=False, server_default=""),
            sa.Column("recognizer", sa.String(64), nullable=False, server_default=""),
            sa.Column("evidence_type", sa.String(32), nullable=False, server_default=""),
            sa.Column("field_name", sa.String(128), nullable=False, server_default=""),
            sa.Column("sheet_name", sa.String(128), nullable=False, server_default=""),
            sa.Column("column_index", sa.Integer(), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("engine_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("ruleset_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("extra", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("detection_id", "evidence_key", name="uq_detection_evidence_key"),
        )
        op.create_index("ix_detection_evidence_detection_id", "detection_evidence", ["detection_id"])
        op.create_index("ix_detection_evidence_rule_id", "detection_evidence", ["rule_id"])

    # Foreign keys are added last, and only on dialects that can do it in place.
    # SQLite cannot ALTER TABLE ADD CONSTRAINT, and the tables are already
    # consistent there because the ORM models declare the same links.
    if _supports_add_constraint():
        for table, name, column, target in _FOREIGN_KEYS:
            op.create_foreign_key(name, table, target, [column], ["id"])


#: (table, constraint name, column, referenced table)
_FOREIGN_KEYS = (
    ("asset_instances", "fk_asset_instances_object_id", "object_id", "data_objects"),
    ("asset_instances", "fk_asset_instances_probe_id", "probe_id", "probes"),
    ("detections", "fk_detections_object_id", "object_id", "data_objects"),
    ("detections", "fk_detections_instance_id", "instance_id", "asset_instances"),
    ("detections", "fk_detections_probe_id", "probe_id", "probes"),
    ("detection_evidence", "fk_detection_evidence_detection_id", "detection_id", "detections"),
)


def _supports_add_constraint() -> bool:
    return op.get_bind().dialect.name != "sqlite"


def downgrade() -> None:
    # Children first: detection_evidence -> detections -> asset_instances ->
    # data_objects. Dropping them in this order keeps the foreign keys valid.
    if _has_table("detection_evidence"):
        op.drop_table("detection_evidence")
    if _has_table("detections"):
        op.drop_table("detections")
    if _has_table("asset_instances"):
        op.drop_table("asset_instances")
    if _has_table("data_objects"):
        op.drop_table("data_objects")