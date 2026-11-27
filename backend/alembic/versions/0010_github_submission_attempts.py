"""Persist an atomic, fail-closed GitHub submission claim.

Revision ID: 0010_github_submission_attempts
Revises: 0009_review_proposal_digest
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_github_submission_attempts"
down_revision = "0009_review_proposal_digest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_submission_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fix_id", sa.Integer(), sa.ForeignKey("fixes.id"), nullable=False, unique=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("proposal_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("github_submission_attempts")
