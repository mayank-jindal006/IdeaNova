"""Allow explicitly permitted local repositories to be scanned.

Revision ID: 0008_permitted_local_repositories
Revises: 0007_reviews_audit_and_scan_findings
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_permitted_local_repositories"
down_revision = "0007_reviews_audit_and_scan_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("repos", sa.Column("local_path", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("repos", "local_path")
