"""Bind local approvals to the exact proposal.

Revision ID: 0009_review_proposal_digest
Revises: 0008_permitted_local_repositories
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_review_proposal_digest"
down_revision = "0008_permitted_local_repositories"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("fix_reviews", sa.Column("proposal_digest", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("fix_reviews", "proposal_digest")
