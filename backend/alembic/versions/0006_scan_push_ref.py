"""Persist the validated Git ref associated with a push scan.

Revision ID: 0006_scan_push_ref
Revises: 0005_remove_untrusted_repo_paths
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_scan_push_ref"
down_revision = "0005_remove_untrusted_repo_paths"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("ref", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "ref")
