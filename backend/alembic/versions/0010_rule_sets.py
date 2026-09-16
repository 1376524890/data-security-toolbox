"""central rule sets and immutable published versions

Revision ID: 0010_rule_sets
Revises: 0009_probe_data_assets
Create Date: 2026-09-16

Additive only: existing deployments keep every row.

Two constraints shape this migration:

* ``0001_initial`` runs ``Base.metadata.create_all``, so a *fresh* database
  already contains whatever the current models declare - including these three
  tables. Every step is therefore guarded by ``_has_table``/``_has_constraint``
  instead of assuming it is the only creator.
* An *existing* deployment is at ``0009`` and has none of these tables, so this
  file is the only creator there. ``rule_sets`` and ``rule_set_versions``
  reference each other, and PostgreSQL rejects a ``CREATE TABLE`` whose foreign
  key points at a table that does not exist yet, so the constraint on
  ``rule_sets`` is added after ``rule_set_versions`` exists rather than inline.

``downgrade`` is provided for completeness and is not part of the upgrade path.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_rule_sets"
down_revision = "0009_probe_data_assets"
branch_labels = None
depends_on = None

ACTIVE_VERSION_FK = "fk_rule_sets_active_version_id"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_constraint(table: str, name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return False
    return any(item.get("name") == name for item in inspector.get_foreign_keys(table))


def _supports_add_constraint() -> bool:
    return op.get_bind().dialect.name != "sqlite"


def upgrade() -> None:
    if not _has_table("rule_sets"):
        op.create_table(
            "rule_sets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("description", sa.String(512), nullable=False, server_default=""),
            sa.Column("active_version_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_rule_sets_name", "rule_sets", ["name"], unique=True)

    if not _has_table("rule_set_versions"):
        op.create_table(
            "rule_set_versions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("rule_set_id", sa.Integer(), sa.ForeignKey("rule_sets.id"), nullable=False),
            sa.Column("version", sa.String(64), nullable=False),
            sa.Column("status", sa.String(16), nullable=False, server_default="published"),
            sa.Column("schema_version", sa.String(16), nullable=False, server_default="1.0"),
            sa.Column("engine_version", sa.String(32), nullable=False, server_default=""),
            sa.Column("min_agent_version", sa.String(32), nullable=False, server_default=""),
            sa.Column("sha256", sa.String(64), nullable=False, server_default=""),
            sa.Column("rule_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("origin_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("changelog", sa.String(512), nullable=False, server_default=""),
            sa.Column("published_by", sa.String(128), nullable=False, server_default=""),
            sa.Column("manifest", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("package", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("rule_set_id", "version", name="uq_ruleset_version"),
        )
        op.create_index("ix_rule_set_versions_rule_set_id", "rule_set_versions", ["rule_set_id"])
        op.create_index("ix_rule_set_versions_version", "rule_set_versions", ["version"])
        op.create_index("ix_rule_set_versions_status", "rule_set_versions", ["status"])

    if not _has_table("rules"):
        op.create_table(
            "rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("rule_set_id", sa.Integer(), sa.ForeignKey("rule_sets.id"), nullable=False),
            sa.Column("rule_id", sa.String(128), nullable=False),
            sa.Column("name", sa.String(255), nullable=False, server_default=""),
            sa.Column("entity", sa.String(64), nullable=False, server_default=""),
            sa.Column("pattern", sa.Text(), nullable=False, server_default=""),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
            sa.Column("validator", sa.String(64), nullable=False, server_default=""),
            sa.Column("field_hints", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("keywords", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("source", sa.String(32), nullable=False, server_default="builtin"),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("rule_set_id", "rule_id", name="uq_rules_set_rule_id"),
        )
        op.create_index("ix_rules_rule_set_id", "rules", ["rule_set_id"])
        op.create_index("ix_rules_rule_id", "rules", ["rule_id"])
        op.create_index("ix_rules_entity", "rules", ["entity"])

    # Added last: both tables now exist, so this is valid on PostgreSQL as well.
    # SQLite cannot ALTER ADD a constraint at all; it is a test-only backend whose
    # schema comes from ``Base.metadata.create_all``, which emits the key inline.
    if _supports_add_constraint() and not _has_constraint("rule_sets", ACTIVE_VERSION_FK):
        op.create_foreign_key(ACTIVE_VERSION_FK, "rule_sets", "rule_set_versions",
                              ["active_version_id"], ["id"])


def downgrade() -> None:
    # `rule_sets.active_version_id` -> `rule_set_versions.id` and
    # `rule_set_versions.rule_set_id` -> `rule_sets.id` form a cycle, so the two
    # tables cannot simply be dropped in either order: the constraint has to go
    # first. `rules` only points at `rule_sets` and can be dropped outright.
    if _has_table("rules"):
        op.drop_table("rules")
    if _has_table("rule_sets") and _has_table("rule_set_versions"):
        for constraint in sa.inspect(op.get_bind()).get_foreign_keys("rule_sets"):
            if constraint.get("referred_table") == "rule_set_versions" and constraint.get("name"):
                op.drop_constraint(constraint["name"], "rule_sets", type_="foreignkey")
    if _has_table("rule_set_versions"):
        op.drop_table("rule_set_versions")
    if _has_table("rule_sets"):
        op.drop_table("rule_sets")
