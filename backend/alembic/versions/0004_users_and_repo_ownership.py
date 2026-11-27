"""Add authenticated users and private repository ownership.

Existing records retain a null owner and are intentionally invisible to all
accounts until an administrator assigns ownership through a controlled DB
migration procedure.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_users_and_repo_ownership"
down_revision = "0003_repo_local_checkout"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("email", sa.String(length=320), nullable=False, unique=True), sa.Column("password_hash", sa.String(length=512), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    with op.batch_alter_table("repos") as batch:
        batch.add_column(sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", name="fk_repos_owner_id_users"), nullable=True))
    op.create_index("ix_repos_owner_id", "repos", ["owner_id"])


def downgrade() -> None:
    op.drop_index("ix_repos_owner_id", table_name="repos")
    op.drop_column("repos", "owner_id")
    op.drop_table("users")
