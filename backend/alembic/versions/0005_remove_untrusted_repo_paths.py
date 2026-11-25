"""Remove client-selected filesystem checkout paths.

Revision ID: 0005_remove_untrusted_repo_paths
Revises: 0004_users_and_repo_ownership
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_remove_untrusted_repo_paths"
down_revision = "0004_users_and_repo_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("repos", "local_path")


def downgrade() -> None:
    op.add_column("repos", sa.Column("local_path", sa.String(), nullable=True))
