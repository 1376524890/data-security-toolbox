"""Let a policy group carry SHA256 fingerprints of risky files."""
import sqlalchemy as sa

from alembic import op

revision = "0019_policy_group_fingerprints"
down_revision = "0018_policy_groups"
branch_labels = depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("policy_groups"):
        return
    columns = {column["name"] for column in inspector.get_columns("policy_groups")}
    if "fingerprints" in columns:
        return
    op.add_column("policy_groups",
                  sa.Column("fingerprints", sa.JSON(), nullable=False, server_default="[]"))
    op.alter_column("policy_groups", "fingerprints", server_default=None)


def downgrade():
    op.drop_column("policy_groups", "fingerprints")
