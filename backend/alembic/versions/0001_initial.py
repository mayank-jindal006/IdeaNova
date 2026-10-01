"""Initial RepoGuard schema.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

# Enums are created explicitly in upgrade(), so table creation must not emit a
# second CREATE TYPE statement.
scan_trigger = postgresql.ENUM("manual", "push", "pull_request", name="scan_trigger", create_type=False)
scan_status = postgresql.ENUM("queued", "running", "done", "failed", name="scan_status", create_type=False)
finding_type = postgresql.ENUM("secret", "dependency", name="finding_type", create_type=False)
severity = postgresql.ENUM("critical", "high", "medium", "low", name="severity", create_type=False)
finding_status = postgresql.ENUM("open", "fix_proposed", "pr_opened", "fixed", "false_positive", "needs_rotation", name="finding_status", create_type=False)
fix_tier = postgresql.ENUM("auto_branch", "pr_review", "flag_only", name="fix_tier", create_type=False)
fix_status = postgresql.ENUM("generated", "validation_failed", "pr_opened", "merged", "rejected", name="fix_status", create_type=False)
feedback_verdict = postgresql.ENUM("true_positive", "false_positive", name="feedback_verdict", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in (scan_trigger, scan_status, finding_type, severity, finding_status, fix_tier, fix_status, feedback_verdict):
        enum_type.create(bind, checkfirst=True)
    op.create_table("repos", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("full_name", sa.String(255), nullable=False, unique=True), sa.Column("default_branch", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("last_scanned_at", sa.DateTime(timezone=True)))
    op.create_table("scans", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False), sa.Column("trigger", scan_trigger, nullable=False), sa.Column("commit_sha", sa.String(64)), sa.Column("status", scan_status, nullable=False), sa.Column("error", sa.Text()), sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)))
    op.create_index("ix_scans_repo_id", "scans", ["repo_id"])
    op.create_table("findings", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False), sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False), sa.Column("fingerprint", sa.String(64), nullable=False), sa.Column("type", finding_type, nullable=False), sa.Column("rule_id", sa.String(255), nullable=False), sa.Column("title", sa.String(500), nullable=False), sa.Column("severity", severity, nullable=False), sa.Column("file_path", sa.String(1024), nullable=False), sa.Column("line", sa.Integer()), sa.Column("commit_sha", sa.String(64)), sa.Column("secret_masked", sa.String(1024)), sa.Column("secret_hash", sa.String(64)), sa.Column("package", sa.String(255)), sa.Column("ecosystem", sa.String(255)), sa.Column("installed_version", sa.String(255)), sa.Column("fixed_version", sa.String(255)), sa.Column("in_history_only", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("confidence", sa.Float(), nullable=False), sa.Column("status", finding_status, nullable=False), sa.Column("owasp_ids", sa.ARRAY(sa.Text()), nullable=False), sa.Column("asvs_ids", sa.ARRAY(sa.Text()), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.UniqueConstraint("repo_id", "fingerprint", name="uq_findings_repo_fingerprint"), sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_findings_confidence"))
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_repo_id", "findings", ["repo_id"])
    op.create_index("ix_findings_repo_status_severity", "findings", ["repo_id", "status", "severity"])
    op.create_table("fixes", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False), sa.Column("explanation", postgresql.JSONB(), nullable=False), sa.Column("edits", postgresql.JSONB(), nullable=False), sa.Column("tier", fix_tier, nullable=False), sa.Column("validation", postgresql.JSONB(), nullable=False), sa.Column("pr_url", sa.String(2048)), sa.Column("pr_number", sa.Integer()), sa.Column("status", fix_status, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.create_index("ix_fixes_finding_id", "fixes", ["finding_id"])
    op.create_table("repo_scores", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False), sa.Column("compliance_score", sa.Integer(), nullable=False), sa.Column("control_results", postgresql.JSONB(), nullable=False), sa.Column("risk_score", sa.Integer(), nullable=False), sa.Column("risk_factors", postgresql.JSONB(), nullable=False), sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False), sa.CheckConstraint("compliance_score >= 0 AND compliance_score <= 100", name="ck_repo_scores_compliance"), sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_repo_scores_risk"))
    op.create_index("ix_repo_scores_repo_id", "repo_scores", ["repo_id"])
    op.create_index("ix_repo_scores_scan_id", "repo_scores", ["scan_id"])
    op.create_table("feedback", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False), sa.Column("verdict", feedback_verdict, nullable=False), sa.Column("note", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.create_index("ix_feedback_finding_id", "feedback", ["finding_id"])


def downgrade() -> None:
    for table in ("feedback", "repo_scores", "fixes", "findings", "scans", "repos"):
        op.drop_table(table)
    bind = op.get_bind()
    for enum_type in (feedback_verdict, fix_status, fix_tier, finding_status, severity, finding_type, scan_status, scan_trigger):
        enum_type.drop(bind, checkfirst=True)
