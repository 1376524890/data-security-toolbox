"""Policy groups: the selectable rule bundle chosen when a task is dispatched."""
import sqlalchemy as sa

from alembic import op

revision = "0018_policy_groups"
down_revision = "0017_file_sources"
branch_labels = depends_on = None

def upgrade():
    if sa.inspect(op.get_bind()).has_table("policy_groups"):
        return
    op.create_table("policy_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(512), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("rule_ids", sa.JSON(), nullable=False),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("keywords", sa.JSON(), nullable=False),
        sa.Column("min_confidence", sa.Float(), nullable=False),
        sa.Column("min_matches", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_policy_groups_name", "policy_groups", ["name"], unique=True)
    op.create_index("ix_policy_groups_enabled", "policy_groups", ["enabled"])

def downgrade():
    op.drop_index("ix_policy_groups_enabled", table_name="policy_groups")
    op.drop_index("ix_policy_groups_name", table_name="policy_groups")
    op.drop_table("policy_groups")
