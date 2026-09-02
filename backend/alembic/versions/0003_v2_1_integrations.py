"""v2.1 integration tables

Revision ID: 0003_v2_1_integrations
Revises: 0002_engine_upgrade
Create Date: 2026-09-02
"""
from alembic import op

from app.models import Base

revision = "0003_v2_1_integrations"
down_revision = "0002_engine_upgrade"
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    for table in ["incidents", "iocs"]:
        op.drop_table(table)
