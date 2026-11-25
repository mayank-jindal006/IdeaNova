"""Initial frozen RepoGuard contract.

Revision ID: 0001_initial_contract
Revises:
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_contract"
down_revision = None
branch_labels = None
depends_on = None

scan_trigger = sa.Enum("manual", "push", "pull_request", name="scantrigger")
scan_status = sa.Enum("queued", "running", "done", "failed", name="scanstatus")
finding_type = sa.Enum("secret", "dependency", name="findingtype")
severity = sa.Enum("critical", "high", "medium", "low", name="severity")
finding_status = sa.Enum("open", "fix_proposed", "pr_opened", "fixed", "false_positive", "needs_rotation", name="findingstatus")
fix_tier = sa.Enum("auto_branch", "pr_review", "flag_only", name="fixtier")
fix_status = sa.Enum("generated", "validation_failed", "pr_opened", "merged", "rejected", name="fixstatus")
feedback_verdict = sa.Enum("true_positive", "false_positive", name="feedbackverdict")


def upgrade() -> None:
    op.create_table("repos", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("full_name", sa.String(), nullable=False, unique=True), sa.Column("default_branch", sa.String(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("last_scanned_at", sa.DateTime(timezone=True)))
    op.create_table("scans", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False), sa.Column("trigger", scan_trigger, nullable=False), sa.Column("commit_sha", sa.String()), sa.Column("status", scan_status, nullable=False), sa.Column("error", sa.Text()), sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)))
    op.create_table("findings", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False), sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False), sa.Column("fingerprint", sa.String(), nullable=False), sa.Column("type", finding_type, nullable=False), sa.Column("rule_id", sa.String(), nullable=False), sa.Column("title", sa.String(), nullable=False), sa.Column("severity", severity, nullable=False), sa.Column("file_path", sa.String()), sa.Column("line", sa.Integer()), sa.Column("commit_sha", sa.String()), sa.Column("secret_masked", sa.String()), sa.Column("secret_hash", sa.String()), sa.Column("package", sa.String()), sa.Column("ecosystem", sa.String()), sa.Column("installed_version", sa.String()), sa.Column("fixed_version", sa.String()), sa.Column("in_history_only", sa.Boolean(), nullable=False), sa.Column("confidence", sa.Float(), nullable=False), sa.Column("status", finding_status, nullable=False), sa.Column("owasp_ids", postgresql.ARRAY(sa.Text()), nullable=False), sa.Column("asvs_ids", postgresql.ARRAY(sa.Text()), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.UniqueConstraint("repo_id", "fingerprint", name="uq_findings_repo_fingerprint"))
    op.create_table("fixes", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False), sa.Column("explanation", postgresql.JSONB(), nullable=False), sa.Column("edits", postgresql.JSONB(), nullable=False), sa.Column("tier", fix_tier, nullable=False), sa.Column("validation", postgresql.JSONB(), nullable=False), sa.Column("pr_url", sa.String()), sa.Column("pr_number", sa.Integer()), sa.Column("status", fix_status, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("repo_scores", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False), sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False), sa.Column("compliance_score", sa.Integer(), nullable=False), sa.Column("control_results", postgresql.JSONB(), nullable=False), sa.Column("risk_score", sa.Integer(), nullable=False), sa.Column("risk_factors", postgresql.JSONB(), nullable=False), sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("feedback", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False), sa.Column("verdict", feedback_verdict, nullable=False), sa.Column("note", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))


def downgrade() -> None:
    for table in ("feedback", "repo_scores", "fixes", "findings", "scans", "repos"):
        op.drop_table(table)
    for enum in (feedback_verdict, fix_status, fix_tier, finding_status, severity, finding_type, scan_status, scan_trigger):
        enum.drop(op.get_bind(), checkfirst=True)
