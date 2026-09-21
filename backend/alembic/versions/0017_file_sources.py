"""Read-only shared-file sources."""
from alembic import op
import sqlalchemy as sa
revision = "0017_file_sources"
down_revision = "0016_database_connections"
branch_labels = depends_on = None

def upgrade():
    if sa.inspect(op.get_bind()).has_table("file_sources"):
        return
    op.create_table("file_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("root_path", sa.String(1024), nullable=False),
        sa.Column("password_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("password_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("password_key_id", sa.String(64), nullable=False),
        sa.Column("host_key_sha256", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("limits", sa.JSON(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=False),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))

def downgrade():
    op.drop_table("file_sources")
