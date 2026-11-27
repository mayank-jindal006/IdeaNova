from __future__ import annotations

from typing import Literal
import hashlib
import os
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, Repo, RepoScore, Scan, ScanStatus, ScanTrigger, User
from app.db.session import SessionLocal, get_db
from app.github_client.client import default_branch
from app.schemas import RepoCreate, RepoOut, ScanHistoryOut, ScanQueuedOut
from app.services.scan_service import run_scan
from app.auth import current_user, owned_repo
from app.core.scan_paths import ScanPathError, ScanRootError, require_scan_root, validate_scan_path
from app.services.audit import record_audit_event

router = APIRouter(prefix="/repos", tags=["repos"])


def _latest_score(db: Session, repo_id: int) -> RepoScore | None:
    return db.scalar(select(RepoScore).where(RepoScore.repo_id == repo_id).order_by(desc(RepoScore.computed_at)).limit(1))


@router.get("")
def list_repos(db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[dict]:
    return [{**RepoOut.model_validate(repo).model_dump(mode="json"), "latest_score": _score_dict(_latest_score(db, repo.id))} for repo in db.scalars(select(Repo).where(Repo.owner_id == user.id).order_by(Repo.id)).all()]


@router.post("")
def create_repo(payload: RepoCreate, db: Session = Depends(get_db), user: User = Depends(current_user)) -> RepoOut:
    local_path = None
    if payload.local_path:
        if os.getenv("REPOGUARD_LOCAL_SCAN_ENABLED", "").lower() != "true":
            raise HTTPException(403, "Local repository scanning is not enabled")
        if ".." in Path(payload.local_path).parts:
            raise HTTPException(422, "Repository path is invalid")
        try:
            checkout = validate_scan_path(payload.local_path)
        except (ScanRootError, ScanPathError):
            raise HTTPException(422, "Repository path is unavailable or outside the permitted scan root") from None
        if not (checkout / ".git").is_dir() or (checkout / ".git").is_symlink() or (checkout / ".git").is_junction():
            raise HTTPException(422, "A local Git repository is required")
        local_path = str(checkout)
        name_hash = hashlib.sha256(os.fsencode(local_path)).hexdigest()[:16]
        full_name = f"local/{name_hash}"
    else:
        full_name = payload.full_name
    if db.scalar(select(Repo).where(Repo.full_name == full_name, Repo.owner_id == user.id)):
        raise HTTPException(409, "Repository is already tracked")
    branch = payload.default_branch or ("main" if local_path else default_branch(full_name))
    repo = Repo(owner_id=user.id, full_name=full_name, default_branch=branch, local_path=local_path)
    db.add(repo)
    db.flush()
    record_audit_event(db, user, "repository.registered", repo_id=repo.id, details={"full_name": repo.full_name})
    db.commit()
    db.refresh(repo)
    return RepoOut.model_validate(repo)


@router.post("/{repo_id}/scan", response_model=ScanQueuedOut)
def queue_scan(repo_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(current_user)) -> ScanQueuedOut:
    owned_repo(db, repo_id, user)
    try:
        require_scan_root()
    except ScanRootError:
        raise HTTPException(503, "Repository scanning is unavailable") from None
    scan = Scan(
        repo_id=repo_id,
        requested_by_user_id=user.id,
        trigger=ScanTrigger.manual,
        status=ScanStatus.queued,
    )
    db.add(scan)
    db.flush()
    record_audit_event(db, user, "scan.queued", repo_id=repo_id, details={"scan_id": scan.id, "trigger": "manual"})
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_background_scan, scan.id)
    return ScanQueuedOut(scan_id=scan.id, status="queued")


@router.get("/{repo_id}/scans", response_model=list[ScanHistoryOut])
def list_repo_scans(
    repo_id: int,
    limit: int = 50,
    offset: int = 0,
    sort_by: Literal["id", "started_at"] = "id",
    sort_order: Literal["asc", "desc"] = "desc",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> list[dict]:
    owned_repo(db, repo_id, user)
    if limit < 1 or limit > 100 or offset < 0:
        raise HTTPException(422, "Pagination parameters are invalid")
    sort_column = {"id": Scan.id, "started_at": Scan.started_at}[sort_by]
    sort_expression = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    scans = db.scalars(
        select(Scan)
        .where(Scan.repo_id == repo_id)
        .order_by(sort_expression, Scan.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [{
        **ScanHistoryOut.model_validate(scan).model_dump(mode="json"),
        "findings_count": db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)) or 0,
    } for scan in scans]


def _background_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        run_scan(db, scan_id)
    finally:
        db.close()


@router.get("/{repo_id}")
def get_repo(repo_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    repo = owned_repo(db, repo_id, user)
    return {"repo": RepoOut.model_validate(repo).model_dump(mode="json"), "latest_score": _score_dict(_latest_score(db, repo_id))}


def _score_dict(score: RepoScore | None) -> dict | None:
    if not score:
        return None
    return {"id": score.id, "repo_id": score.repo_id, "scan_id": score.scan_id, "compliance_score": score.compliance_score, "control_results": score.control_results, "risk_score": score.risk_score, "risk_factors": score.risk_factors, "computed_at": score.computed_at}
