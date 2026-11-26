from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
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
    default_branch: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


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
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), nullable=False)
    scanner_status: Mapped[Optional[dict]] = mapped_column(JsonValue)
    error: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("repo_id", "fingerprint", name="uq_findings_repo_fingerprint"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[FindingType] = mapped_column(Enum(FindingType), nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
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
    tier: Mapped[FixTier] = mapped_column(Enum(FixTier), nullable=False)
    validation: Mapped[dict] = mapped_column(JsonValue, nullable=False)
    pr_url: Mapped[Optional[str]] = mapped_column(String)
    pr_number: Mapped[Optional[int]] = mapped_column(Integer)
    status: Mapped[FixStatus] = mapped_column(Enum(FixStatus), nullable=False)
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
