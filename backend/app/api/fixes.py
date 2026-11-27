from __future__ import annotations

import hashlib
import hmac
import shutil
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import desc, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.ai.fix import validate_target_path
from app.auth import current_user
from app.core.scan_paths import require_scan_root, validate_scan_path
from app.db.models import AuditLog, Finding, Fix, FixReview, FixStatus, GitHubSubmissionAttempt, Repo, User
from app.db.session import get_db
from app.github_client.client import clone_repo, commit_file_changes, create_branch, open_pull_request
from app.schemas import FixOut, FixReviewCreate, FixReviewOut, OpenPrOut
from app.services.audit import record_audit_event
from app.services.fix_validation import validate_fix_candidate
from app.services.proposal_integrity import proposal_digest
from app.services.manual_patch_export import ExportRejected, build_export

router = APIRouter(prefix="/fixes", tags=["fixes"])


def _owned_fix(db: Session, fix_id: int, user: User, *, lock: bool = False) -> tuple[Fix, Finding, Repo]:
    query = (
        select(Fix, Finding, Repo)
        .join(Finding, Fix.finding_id == Finding.id)
        .join(Repo, Finding.repo_id == Repo.id)
        .where(Fix.id == fix_id, Repo.owner_id == user.id)
    )
    if lock:
        query = query.with_for_update(of=Fix)
    row = db.execute(query).first()
    if not row:
        raise HTTPException(404, "Fix not found")
    return row


def require_connected_github(user: User, repo: Repo) -> None:
    """Fail closed until an owner-bound GitHub App authorization exists."""
    raise HTTPException(503, "GitHub account connection is not configured")


def _fix_out(fix: Fix) -> FixOut:
    return FixOut.model_validate({
        "id": fix.id,
        "finding_id": fix.finding_id,
        "explanation": fix.explanation,
        "edits": fix.edits,
        "patch": fix.patch,
        "target_file": fix.target_file,
        "risk_level": fix.risk_level,
        "model": fix.model,
        "pr_url": fix.pr_url,
        "pr_number": fix.pr_number,
        "tier": fix.tier.value,
        "validation": fix.validation,
        "status": fix.status.value,
        "created_at": fix.created_at,
    })


@router.get("/{fix_id}")
def get_fix(fix_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    fix, finding, _ = _owned_fix(db, fix_id, user)
    reviews = db.scalars(
        select(FixReview).where(FixReview.fix_id == fix.id).order_by(FixReview.created_at, FixReview.id)
    ).all()
    return {
        "fix": _fix_out(fix).model_dump(mode="json"),
        "reviews": [FixReviewOut.model_validate(review).model_dump(mode="json") for review in reviews],
        "finding_id": finding.id,
    }


@router.get("/{fix_id}/pr-eligibility")
def pr_eligibility(fix_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    _, _, repo = _owned_fix(db, fix_id, user)
    if repo.local_path:
        return {"eligible": False, "reason": "Pull requests are unavailable for local repositories", "connection": "not_connected"}
    return {"eligible": False, "reason": "GitHub account connection is not configured", "connection": "not_connected"}


def _export_package(db: Session, fix_id: int, user: User):
    fix, finding, repo = _owned_fix(db, fix_id, user)
    latest_review = db.scalar(select(FixReview).where(FixReview.fix_id == fix.id).order_by(desc(FixReview.created_at), desc(FixReview.id)).limit(1))
    latest_fix_id = db.scalar(select(Fix.id).where(Fix.finding_id == finding.id).order_by(desc(Fix.id)).limit(1))
    return build_export(fix, finding, repo, latest_review, user, latest_fix_id), fix, finding, repo


@router.get("/{fix_id}/export-status")
def patch_export_status(fix_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    try:
        (_, manifest), _, _, _ = _export_package(db, fix_id, user)
    except ExportRejected as exc:
        return {"eligible": False, "reason": str(exc), "proposal_digest": None}
    return {"eligible": True, "reason": None, "proposal_digest": manifest["proposal_digest"]}


@router.post("/{fix_id}/export")
def export_patch(fix_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> Response:
    try:
        (archive, manifest), fix, finding, repo = _export_package(db, fix_id, user)
    except (ExportRejected, HTTPException) as exc:
        record_audit_event(db, user, "fix.export_rejected", details={"reason": "not_eligible"})
        db.commit()
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(409, str(exc)) from None
    record_audit_event(db, user, "fix.exported", repo_id=repo.id, finding_id=finding.id, fix_id=fix.id, details={"proposal_digest": manifest["proposal_digest"], "approval_digest": manifest["approval_digest"], "validation_digest": manifest["validated_proposal_digest"], "patch_sha256": manifest["patch_sha256"], "exported_at": manifest["created_at"]})
    db.commit()
    return Response(content=archive, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="repoguard-fix-{fix.id}.zip"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.post("/{fix_id}/review")
def review_fix(
    fix_id: int,
    payload: FixReviewCreate,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict:
    fix, finding, repo = _owned_fix(db, fix_id, user)
    if fix.status != FixStatus.pending_review:
        raise HTTPException(409, "Fix is not awaiting review")
    if payload.decision == "approved" and (
        not fix.patch
        or fix.validation.get("patch_syntax") != "passed"
        or fix.validation.get("target_exists") is not True
    ):
        raise HTTPException(409, "Fix proposal did not pass safe patch checks")

    note = payload.note
    if note:
        from app.ai.redaction import redact_context_for_llm

        note = redact_context_for_llm(note, [])[:2000]
    review = FixReview(
        fix_id=fix.id,
        reviewer_id=user.id,
        reviewer_email=user.email,
        decision=payload.decision,
        note=note,
        proposal_digest=proposal_digest(fix) if payload.decision == "approved" else None,
    )
    fix.status = FixStatus.approved if payload.decision == "approved" else FixStatus.rejected
    record_audit_event(
        db,
        user,
        f"fix.{payload.decision}",
        repo_id=repo.id,
        finding_id=finding.id,
        fix_id=fix.id,
        details={"decision": payload.decision},
    )
    db.add(review)
    db.commit()
    db.refresh(fix)
    return {
        "fix": _fix_out(fix).model_dump(mode="json"),
        "review": FixReviewOut.model_validate(review).model_dump(mode="json"),
    }


@router.post("/{fix_id}/validate")
def validate_fix(
    fix_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict:
    fix, finding, repo = _owned_fix(db, fix_id, user)
    latest_review = db.scalar(
        select(FixReview)
        .where(FixReview.fix_id == fix.id)
        .order_by(desc(FixReview.created_at), desc(FixReview.id))
        .limit(1)
    )
    if (
        fix.status not in {FixStatus.approved, FixStatus.validation_failed}
        or not latest_review
        or latest_review.decision != "approved"
    ):
        raise HTTPException(409, "Fix must be explicitly approved before validation")

    if (
        latest_review.reviewer_id != user.id
        or not latest_review.proposal_digest
        or not hmac.compare_digest(latest_review.proposal_digest, proposal_digest(fix))
    ):
        raise HTTPException(409, "The approved proposal has changed; generate and review a new proposal")

    validated_digest = proposal_digest(fix)
    validation = validate_fix_candidate(repo, finding, fix)
    db.refresh(fix)
    db.refresh(latest_review)
    db.refresh(finding)
    db.refresh(repo)
    if repo.owner_id != user.id or finding.repo_id != repo.id or fix.finding_id != finding.id:
        raise HTTPException(404, "Fix not found")
    if (
        fix.status not in {FixStatus.approved, FixStatus.validation_failed}
        or latest_review.decision != "approved"
        or latest_review.reviewer_id != user.id
        or latest_review.proposal_digest != validated_digest
        or not hmac.compare_digest(validated_digest, proposal_digest(fix))
    ):
        raise HTTPException(409, "The proposal changed during validation")
    validation["proposal_digest"] = validated_digest
    fix.validation = validation
    passed = (
        fix.validation.get("patch_syntax") == "passed"
        and fix.validation.get("target_exists") is True
        and fix.validation.get("security_rescan") == "passed"
        and fix.validation.get("syntax_ok") is True
    )
    fix.status = FixStatus.validation_passed if passed else FixStatus.validation_failed
    record_audit_event(
        db,
        user,
        "fix.validation_completed",
        repo_id=repo.id,
        finding_id=finding.id,
        fix_id=fix.id,
        details={"status": fix.status.value},
    )
    db.commit()
    db.refresh(fix)
    return {"fix": _fix_out(fix).model_dump(mode="json")}


@router.post("/{fix_id}/open-pr", response_model=OpenPrOut)
def open_pr(fix_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> OpenPrOut:
    fix, finding, repo = _owned_fix(db, fix_id, user, lock=True)
    if repo.local_path:
        raise HTTPException(409, "Pull requests are unavailable for local repositories")
    latest_review = db.scalar(
        select(FixReview)
        .where(FixReview.fix_id == fix.id)
        .order_by(desc(FixReview.created_at), desc(FixReview.id))
        .limit(1)
    )
    if (
        fix.status != FixStatus.validation_passed
        or not latest_review
        or latest_review.decision != "approved"
        or not fix.patch
        or not fix.edits
        or len(fix.edits) != 1
    ):
        raise HTTPException(409, "Fix must be approved and validated before opening a pull request")

    current_digest = proposal_digest(fix)
    validation_digest = fix.validation.get("proposal_digest") if isinstance(fix.validation, dict) else None
    latest_fix_id = db.scalar(select(Fix.id).where(Fix.finding_id == finding.id).order_by(desc(Fix.id)).limit(1))
    if (
        fix.id != latest_fix_id
        or latest_review.reviewer_id != user.id
        or not isinstance(latest_review.proposal_digest, str)
        or not isinstance(validation_digest, str)
        or not hmac.compare_digest(latest_review.proposal_digest, current_digest)
        or not hmac.compare_digest(validation_digest, current_digest)
    ):
        raise HTTPException(409, "Approval or validation does not match the latest proposal")

    require_connected_github(user, repo)

    # Reserve the submission under a database row lock before any external write.
    # An interrupted attempt is deliberately not retried automatically: a GitHub
    # timeout or failed database commit may have hidden a successful remote write.
    prior_attempt = db.scalar(select(AuditLog.id).where(AuditLog.fix_id == fix.id, AuditLog.action == "fix.pr_submission_started").limit(1))
    if prior_attempt:
        raise HTTPException(409, "A submission was already attempted; inspect the remote repository before any manual recovery")
    attempt = GitHubSubmissionAttempt(fix_id=fix.id, user_id=user.id, repo_id=repo.id, proposal_digest=current_digest, status="started", stage="target_check")
    db.add(attempt)
    record_audit_event(db, user, "fix.pr_submission_started", repo_id=repo.id, finding_id=finding.id, fix_id=fix.id, details={"branch": f"repoguard/fix-{finding.id}-{fix.id}"})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A submission was already attempted; inspect the remote repository before any manual recovery") from None

    stage = "target_check"
    try:
        target_file = validate_target_path(fix.target_file or "")
        if fix.edits[0].get("file_path") != target_file or not fix.base_hash:
            raise ValueError("Fix target metadata is invalid")
        require_scan_root()
        checkout_path = clone_repo(repo.full_name)
        try:
            checkout = validate_scan_path(checkout_path)
            target = (checkout / Path(*target_file.split("/"))).resolve(strict=True)
            if not target.is_relative_to(checkout) or not target.is_file():
                raise ValueError("Fix target is unavailable")
            current_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            if current_hash != fix.base_hash:
                raise ValueError("Fix target changed after validation")
            base_sha = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        finally:
            shutil.rmtree(checkout_path, ignore_errors=True)

        branch = f"repoguard/fix-{finding.id}-{fix.id}"
        stage = "branch_creation"
        attempt.stage = stage
        db.commit()
        create_branch(repo.full_name, branch, repo.default_branch, base_sha=base_sha)
        stage = "file_commit"
        attempt.stage = stage
        db.commit()
        commit_file_changes(repo.full_name, branch, fix.edits)
        body = (
            f"## RepoGuard validated remediation for finding {finding.id}\n\n"
            "This is an approved proposal validated in a disposable checkout. "
            "Review the patch and run the project's own test suite before merging. "
            "Nothing is merged automatically."
        )
        stage = "pull_request_creation"
        attempt.stage = stage
        db.commit()
        pr_url, pr_number = open_pull_request(
            repo.full_name,
            branch,
            repo.default_branch,
            f"RepoGuard remediation for finding {finding.id}",
            body,
        )
    except Exception:
        attempt.status = "failed"
        attempt.stage = stage
        record_audit_event(
            db,
            user,
            "fix.pr_creation_failed",
            repo_id=repo.id,
            finding_id=finding.id,
            fix_id=fix.id,
            details={"reason": "github_operation_failed_or_target_changed", "stage": stage},
        )
        db.commit()
        raise HTTPException(502, "The approved remediation pull request could not be created") from None

    fix.pr_url, fix.pr_number, fix.status = pr_url, pr_number, FixStatus.pr_opened
    attempt.status = "completed"
    attempt.stage = "completed"
    record_audit_event(
        db,
        user,
        "fix.pr_opened",
        repo_id=repo.id,
        finding_id=finding.id,
        fix_id=fix.id,
        details={"pr_number": pr_number},
    )
    db.commit()
    return OpenPrOut(pr_url=pr_url, pr_number=pr_number)
