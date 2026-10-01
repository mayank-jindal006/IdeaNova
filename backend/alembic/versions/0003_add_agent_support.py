"""add self-healing agent support

Revision ID: 0003_add_agent_support
Revises: 0002_add_finding_columns
Create Date: 2026-10-01
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0003_add_agent_support"
down_revision = "0002_add_finding_columns"
branch_labels = None
depends_on = None

ci_status = postgresql.ENUM("none", "pending", "passed", "failed", name="ci_status", create_type=False)
agent_step = postgresql.ENUM("detected", "fix_generated", "skipped", "pr_opened", "ci_pending", "ci_passed", "ci_failed", "repaired", "repair_failed", "gave_up", "error", name="agent_step", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    ci_status.create(bind, checkfirst=True)
    agent_step.create(bind, checkfirst=True)
    op.add_column("repos", sa.Column("auto_fix_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("fixes", sa.Column("branch", sa.String(length=255), nullable=True))
    op.add_column("fixes", sa.Column("ci_status", ci_status, nullable=False, server_default="none"))
    op.add_column("fixes", sa.Column("repair_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("fixes", sa.Column("head_sha", sa.String(length=64), nullable=True))
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("fix_id", sa.Integer(), sa.ForeignKey("fixes.id"), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("step", agent_step, nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_agent_runs_repo_id", "agent_runs", ["repo_id"])
    op.create_index("ix_agent_runs_finding_id", "agent_runs", ["finding_id"])
    op.create_index("ix_agent_runs_fix_id", "agent_runs", ["fix_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_runs_fix_id", table_name="agent_runs")
    op.drop_index("ix_agent_runs_finding_id", table_name="agent_runs")
    op.drop_index("ix_agent_runs_repo_id", table_name="agent_runs")
    op.drop_table("agent_runs")
    op.drop_column("fixes", "head_sha")
    op.drop_column("fixes", "repair_attempts")
    op.drop_column("fixes", "ci_status")
    op.drop_column("fixes", "branch")
    op.drop_column("repos", "auto_fix_enabled")
    bind = op.get_bind()
    agent_step.drop(bind, checkfirst=True)
    ci_status.drop(bind, checkfirst=True)
