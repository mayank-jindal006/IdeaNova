from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, CheckConstraint, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanTrigger(str, enum.Enum):
    manual = "manual"
    push = "push"
    pull_request = "pull_request"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class FindingType(str, enum.Enum):
    secret = "secret"
    dependency = "dependency"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class FindingStatus(str, enum.Enum):
    open = "open"
    fix_proposed = "fix_proposed"
    pr_opened = "pr_opened"
    fixed = "fixed"
    false_positive = "false_positive"
    needs_rotation = "needs_rotation"


class FixTier(str, enum.Enum):
    auto_branch = "auto_branch"
    pr_review = "pr_review"
    flag_only = "flag_only"


class FixStatus(str, enum.Enum):
    generated = "generated"
    pending_review = "pending_review"
    approved = "approved"
    applied = "applied"
    validation_passed = "validation_passed"
    validation_failed = "validation_failed"
    pr_opened = "pr_opened"
    merged = "merged"
    rejected = "rejected"


class FeedbackVerdict(str, enum.Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"


JsonValue = JSON().with_variant(JSONB, "postgresql")
TextArray = JSON().with_variant(ARRAY(Text), "postgresql")


class Repo(Base):
    __tablename__ = "repos"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    full_name: Mapped[str] = mapped_column(String, nullable=False)
    local_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_branch: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    @property
    def source_type(self) -> str:
        return "local" if self.local_path else "github"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False)
    trigger: Mapped[ScanTrigger] = mapped_column(Enum(ScanTrigger), nullable=False)
    ref: Mapped[Optional[str]] = mapped_column(String)
    commit_sha: Mapped[Optional[str]] = mapped_column(String)
    requested_by_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), nullable=False)
    scanner_status: Mapped[Optional[dict]] = mapped_column(JsonValue)
    error: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
        Index("ix_findings_repo_created_at", "repo_id", "created_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[Severity]] = mapped_column(Enum(Severity))
    scanner: Mapped[str] = mapped_column(String, nullable=False, default="unknown")
    file_path: Mapped[Optional[str]] = mapped_column(String)
    line: Mapped[Optional[int]] = mapped_column(Integer)
    commit_sha: Mapped[Optional[str]] = mapped_column(String)
    secret_masked: Mapped[Optional[str]] = mapped_column(String)
    secret_hash: Mapped[Optional[str]] = mapped_column(String)
    package: Mapped[Optional[str]] = mapped_column(String)
    ecosystem: Mapped[Optional[str]] = mapped_column(String)
    installed_version: Mapped[Optional[str]] = mapped_column(String)
    affected_versions: Mapped[Optional[str]] = mapped_column(Text)
    fixed_version: Mapped[Optional[str]] = mapped_column(String)
    advisory_id: Mapped[Optional[str]] = mapped_column(String)
    aliases: Mapped[list[str]] = mapped_column(TextArray, nullable=False, default=list)
    references: Mapped[list[str]] = mapped_column(TextArray, nullable=False, default=list)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    in_history_only: Mapped[bool] = mapped_column(nullable=False, default=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), nullable=False)
    owasp_ids: Mapped[list[str]] = mapped_column(TextArray, nullable=False, default=list)
    asvs_ids: Mapped[list[str]] = mapped_column(TextArray, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class Fix(Base):
    __tablename__ = "fixes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    explanation: Mapped[dict] = mapped_column(JsonValue, nullable=False)
    edits: Mapped[list] = mapped_column(JsonValue, nullable=False)
    patch: Mapped[Optional[str]] = mapped_column(Text)
    target_file: Mapped[Optional[str]] = mapped_column(String)
    base_hash: Mapped[Optional[str]] = mapped_column(String(64))
    risk_level: Mapped[Optional[str]] = mapped_column(String)
    model: Mapped[Optional[str]] = mapped_column(String)
    tier: Mapped[FixTier] = mapped_column(Enum(FixTier), nullable=False)
    validation: Mapped[dict] = mapped_column(JsonValue, nullable=False)
    pr_url: Mapped[Optional[str]] = mapped_column(String)
    pr_number: Mapped[Optional[int]] = mapped_column(Integer)
    status: Mapped[FixStatus] = mapped_column(Enum(FixStatus), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class FixReview(Base):
    __tablename__ = "fix_reviews"
    __table_args__ = (
        CheckConstraint("decision IN ('approved', 'rejected')", name="ck_fix_reviews_decision"),
        Index("ix_fix_reviews_fix_created_at", "fix_id", "created_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fix_id: Mapped[int] = mapped_column(ForeignKey("fixes.id"), nullable=False)
    reviewer_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewer_email: Mapped[str] = mapped_column(String(320), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    proposal_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AiRequestLog(Base):
    __tablename__ = "ai_request_logs"
    __table_args__ = (
        Index("ix_ai_request_logs_finding_created_at", "finding_id", "created_at"),
        Index("ix_ai_request_logs_user_created_at", "user_id", "created_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[Optional[str]] = mapped_column(String)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    failure_category: Mapped[Optional[str]] = mapped_column(String(64))
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    result: Mapped[Optional[dict]] = mapped_column(JsonValue)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GitHubSubmissionAttempt(Base):
    __tablename__ = "github_submission_attempts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fix_id: Mapped[int] = mapped_column(ForeignKey("fixes.id"), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False)
    proposal_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_user_created_at", "user_id", "created_at"),
        Index("ix_audit_logs_repo_created_at", "repo_id", "created_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_email: Mapped[Optional[str]] = mapped_column(String(320))
    repo_id: Mapped[Optional[int]] = mapped_column(ForeignKey("repos.id", ondelete="SET NULL"), nullable=True)
    finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    fix_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fixes.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(JsonValue, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RepoScore(Base):
    __tablename__ = "repo_scores"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    compliance_score: Mapped[int] = mapped_column(Integer, nullable=False)
    control_results: Mapped[list] = mapped_column(JsonValue, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_factors: Mapped[list] = mapped_column(JsonValue, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    verdict: Mapped[FeedbackVerdict] = mapped_column(Enum(FeedbackVerdict), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
