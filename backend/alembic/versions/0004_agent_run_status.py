"""add agent run status

Revision ID: 0004_agent_run_status
Revises: 0003_add_agent_support
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_agent_run_status"
down_revision = "0003_add_agent_support"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("agent_runs", "step", type_=sa.String(length=64), postgresql_using="step::text")
    op.add_column("agent_runs", sa.Column("status", sa.String(length=64), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("agent_runs", "status")
