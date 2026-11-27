"""Persist scan-scoped findings, AI suggestions, reviews, and audit events.

Revision ID: 0007_reviews_audit_and_scan_findings
Revises: 0006_scan_push_ref
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007_reviews_audit_and_scan_findings"
down_revision = "0006_scan_push_ref"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in ("pending_review", "approved", "applied", "validation_passed"):
            op.execute(sa.text(f"ALTER TYPE fixstatus ADD VALUE IF NOT EXISTS '{value}'"))

    with op.batch_alter_table("findings") as batch:
        batch.drop_constraint("uq_findings_repo_fingerprint", type_="unique")
        batch.create_unique_constraint("uq_findings_scan_fingerprint", ["scan_id", "fingerprint"])
    op.create_index("ix_findings_repo_created_at", "findings", ["repo_id", "created_at"])
    op.add_column("findings", sa.Column("description", sa.Text(), nullable=True))
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("requested_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_scans_requested_by_user_id_users"), nullable=True))
    op.create_index("ix_scans_requested_by_user_id", "scans", ["requested_by_user_id"])

    op.add_column("fixes", sa.Column("patch", sa.Text(), nullable=True))
    op.add_column("fixes", sa.Column("target_file", sa.String(), nullable=True))
    op.add_column("fixes", sa.Column("base_hash", sa.String(length=64), nullable=True))
    op.add_column("fixes", sa.Column("risk_level", sa.String(), nullable=True))
    op.add_column("fixes", sa.Column("model", sa.String(), nullable=True))
    with op.batch_alter_table("fixes") as batch:
        batch.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))

    op.create_table(
        "fix_reviews",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fix_id", sa.Integer(), sa.ForeignKey("fixes.id"), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewer_email", sa.String(length=320), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("decision IN ('approved', 'rejected')", name="ck_fix_reviews_decision"),
    )
    op.create_index("ix_fix_reviews_fix_created_at", "fix_reviews", ["fix_id", "created_at"])

    op.create_table(
        "ai_request_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("failure_category", sa.String(length=64), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("result", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ai_request_logs_finding_created_at", "ai_request_logs", ["finding_id", "created_at"])
    op.create_index("ix_ai_request_logs_user_created_at", "ai_request_logs", ["user_id", "created_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("fix_id", sa.Integer(), sa.ForeignKey("fixes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False, server_default=sa.text("'{}'::jsonb" if bind.dialect.name == "postgresql" else "'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_user_created_at", "audit_logs", ["user_id", "created_at"])
    op.create_index("ix_audit_logs_repo_created_at", "audit_logs", ["repo_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_repo_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_created_at", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_ai_request_logs_user_created_at", table_name="ai_request_logs")
    op.drop_index("ix_ai_request_logs_finding_created_at", table_name="ai_request_logs")
    op.drop_table("ai_request_logs")
    op.drop_index("ix_fix_reviews_fix_created_at", table_name="fix_reviews")
    op.drop_table("fix_reviews")
    op.drop_column("fixes", "updated_at")
    op.drop_column("fixes", "model")
    op.drop_column("fixes", "risk_level")
    op.drop_column("fixes", "base_hash")
    op.drop_column("fixes", "target_file")
    op.drop_column("fixes", "patch")
    op.drop_index("ix_findings_repo_created_at", table_name="findings")
    op.drop_column("findings", "description")
    op.drop_index("ix_scans_requested_by_user_id", table_name="scans")
    op.drop_column("scans", "requested_by_user_id")
    op.drop_constraint("uq_findings_scan_fingerprint", "findings", type_="unique")
    op.create_unique_constraint("uq_findings_repo_fingerprint", "findings", ["repo_id", "fingerprint"])
