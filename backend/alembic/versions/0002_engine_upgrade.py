"""engine upgrade schema

Revision ID: 0002_engine_upgrade
Revises: 0001_initial
Create Date: 2026-09-02
"""
from alembic import op
from app.models import Base

revision = "0002_engine_upgrade"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    for table in ["detection_findings", "vulnerabilities", "data_assets", "graph_relations"]:
        op.drop_table(table)

