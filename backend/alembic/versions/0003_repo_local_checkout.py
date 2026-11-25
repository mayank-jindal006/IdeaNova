"""Persist the selected development checkout for database-backed scans.

Revision ID: 0003_repo_local_checkout
Revises: 0002_scanner_contract_fields
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_repo_local_checkout"
down_revision = "0002_scanner_contract_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("repos", sa.Column("local_path", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("repos", "local_path")
