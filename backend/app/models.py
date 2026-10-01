import enum
from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

JSONType = JSON().with_variant(JSONB, "postgresql")
TextArray = JSON().with_variant(ARRAY(Text), "postgresql")


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
    validation_failed = "validation_failed"
    pr_opened = "pr_opened"
    merged = "merged"
    rejected = "rejected"


class CIStatus(str, enum.Enum):
    none = "none"
    pending = "pending"
    passed = "passed"
    failed = "failed"


class AgentStep(str, enum.Enum):
    detected = "detected"
    fix_generated = "fix_generated"
    skipped = "skipped"
    pr_opened = "pr_opened"
    ci_pending = "ci_pending"
    ci_passed = "ci_passed"
    ci_failed = "ci_failed"
    repaired = "repaired"
    repair_failed = "repair_failed"
    gave_up = "gave_up"
    error = "error"


class FeedbackVerdict(str, enum.Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"


class Repo(Base):
    __tablename__ = "repos"
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    auto_fix_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    scans: Mapped[list["Scan"]] = relationship(back_populates="repo", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="repo", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False, index=True)
    trigger: Mapped[ScanTrigger] = mapped_column(Enum(ScanTrigger, name="scan_trigger"), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.queued)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    repo: Mapped[Repo] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("repo_id", "fingerprint", name="uq_findings_repo_fingerprint"), CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_findings_confidence"), Index("ix_findings_repo_status_severity", "repo_id", "status", "severity"))
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[FindingType] = mapped_column(Enum(FindingType, name="finding_type"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line: Mapped[int | None] = mapped_column(Integer)
    start_column: Mapped[int | None] = mapped_column(Integer)
    end_column: Mapped[int | None] = mapped_column(Integer)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    secret_masked: Mapped[str | None] = mapped_column(String(1024))
    secret_hash: Mapped[str | None] = mapped_column(String(64))
    package: Mapped[str | None] = mapped_column(String(255))
    ecosystem: Mapped[str | None] = mapped_column(String(255))
    installed_version: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    in_history_only: Mapped[bool] = mapped_column(nullable=False, default=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus, name="finding_status"), nullable=False, default=FindingStatus.open)
    owasp_ids: Mapped[list[str]] = mapped_column(TextArray, nullable=False, default=list)
    asvs_ids: Mapped[list[str]] = mapped_column(TextArray, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    repo: Mapped[Repo] = relationship(back_populates="findings")
    scan: Mapped[Scan] = relationship(back_populates="findings")
    fixes: Mapped[list["Fix"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    feedback: Mapped[list["Feedback"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class Fix(Base):
    __tablename__ = "fixes"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    explanation: Mapped[dict] = mapped_column(JSONType, nullable=False)
    edits: Mapped[list] = mapped_column(JSONType, nullable=False)
    tier: Mapped[FixTier] = mapped_column(Enum(FixTier, name="fix_tier"), nullable=False)
    validation: Mapped[dict] = mapped_column(JSONType, nullable=False)
    pr_url: Mapped[str | None] = mapped_column(String(2048))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    branch: Mapped[str | None] = mapped_column(String(255))
    ci_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    repair_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    head_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[FixStatus] = mapped_column(Enum(FixStatus, name="fix_status"), nullable=False, default=FixStatus.generated)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finding: Mapped[Finding] = relationship(back_populates="fixes")


class RepoScore(Base):
    __tablename__ = "repo_scores"
    __table_args__ = (CheckConstraint("compliance_score >= 0 AND compliance_score <= 100", name="ck_repo_scores_compliance"), CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_repo_scores_risk"))
    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    compliance_score: Mapped[int] = mapped_column(Integer, nullable=False)
    control_results: Mapped[list] = mapped_column(JSONType, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_factors: Mapped[list] = mapped_column(JSONType, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    verdict: Mapped[FeedbackVerdict] = mapped_column(Enum(FeedbackVerdict, name="feedback_verdict"), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finding: Mapped[Finding] = relationship(back_populates="feedback")


class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), index=True)
    fix_id: Mapped[int | None] = mapped_column(ForeignKey("fixes.id"), index=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    step: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="", server_default="")
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
