"""Support per-tenant repository tracking and revoke logged-out tokens.

Revision ID: 0007_phase7_deployment
Revises: 0006_scan_push_ref
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_phase7_deployment"
down_revision = "0006_scan_push_ref"
branch_labels = None
depends_on = None


def upgrade() -> None:
    duplicates = op.get_bind().execute(
        sa.text(
            "SELECT 1 FROM repos WHERE owner_id IS NOT NULL "
            "GROUP BY owner_id, lower(full_name) HAVING count(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicates:
        raise RuntimeError(
            "Cannot enable tenant repository uniqueness until duplicate records are reviewed"
        )
    op.create_index(
        "uq_repos_owner_full_name_ci",
        "repos",
        ["owner_id", sa.text("lower(full_name)")],
        unique=True,
    )
    op.drop_constraint("repos_full_name_key", "repos", type_="unique")
    op.create_table(
        "revoked_tokens",
        sa.Column("token_id", sa.String(length=64), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])


def downgrade() -> None:
    duplicates = op.get_bind().execute(
        sa.text(
            "SELECT 1 FROM repos GROUP BY full_name HAVING count(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicates:
        raise RuntimeError(
            "Cannot restore global repository uniqueness while duplicate records exist"
        )
    op.drop_index("ix_revoked_tokens_expires_at", table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
    op.drop_index("uq_repos_owner_full_name_ci", table_name="repos")
    op.create_unique_constraint("repos_full_name_key", "repos", ["full_name"])
