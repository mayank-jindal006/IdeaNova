"""store CI status as nullable text

Revision ID: 0005_ci_status_text
Revises: 0004_agent_run_status
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_ci_status_text"
down_revision = "0004_agent_run_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "fixes",
        "ci_status",
        type_=sa.String(length=32),
        nullable=True,
        server_default=None,
        postgresql_using="ci_status::text",
    )
    op.execute("DROP TYPE IF EXISTS ci_status")


def downgrade() -> None:
    op.execute("CREATE TYPE ci_status AS ENUM ('none', 'pending', 'passed', 'failed')")
    op.alter_column(
        "fixes",
        "ci_status",
        type_=sa.Enum("none", "pending", "passed", "failed", name="ci_status"),
        nullable=False,
        server_default="none",
        postgresql_using="ci_status::ci_status",
    )
