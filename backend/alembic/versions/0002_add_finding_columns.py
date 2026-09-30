"""add finding source columns

Revision ID: 0002_add_finding_columns
Revises: 0001_initial
Create Date: 2026-09-30
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_add_finding_columns"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("start_column", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("end_column", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "end_column")
    op.drop_column("findings", "start_column")
