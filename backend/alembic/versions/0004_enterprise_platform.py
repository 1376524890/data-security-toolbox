"""enterprise platform tables

Revision ID: 0004_enterprise_platform
Revises: 0003_v2_1_integrations
Create Date: 2026-09-02
"""
from alembic import op

from app.models import Base

revision = "0004_enterprise_platform"
down_revision = "0003_v2_1_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    for table in ["local_cves", "offline_resources", "integration_status"]:
        op.drop_table(table)
