from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, Repo, RepoScore, Scan, ScanStatus, ScanTrigger, User
from app.db.session import SessionLocal, get_db
from app.github_client.client import default_branch
from app.schemas import RepoCreate, RepoOut, ScanHistoryOut, ScanQueuedOut
from app.services.scan_service import run_scan
from app.auth import current_user, owned_repo
from app.core.scan_paths import ScanRootError, require_scan_root

router = APIRouter(prefix="/repos", tags=["repos"])


def _latest_score(db: Session, repo_id: int) -> RepoScore | None:
    return db.scalar(select(RepoScore).where(RepoScore.repo_id == repo_id).order_by(desc(RepoScore.computed_at)).limit(1))


@router.get("")
def list_repos(db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[dict]:
    return [{**RepoOut.model_validate(repo).model_dump(mode="json"), "latest_score": _score_dict(_latest_score(db, repo.id))} for repo in db.scalars(select(Repo).where(Repo.owner_id == user.id).order_by(Repo.id)).all()]


@router.post("")
def create_repo(payload: RepoCreate, db: Session = Depends(get_db), user: User = Depends(current_user)) -> RepoOut:
    if db.scalar(select(Repo).where(Repo.full_name == payload.full_name, Repo.owner_id == user.id)):
        raise HTTPException(409, "Repository is already tracked")
    branch = payload.default_branch or default_branch(payload.full_name)
    repo = Repo(owner_id=user.id, full_name=payload.full_name, default_branch=branch)
    db.add(repo)
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
    scan = Scan(repo_id=repo_id, trigger=ScanTrigger.manual, status=ScanStatus.queued)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_background_scan, scan.id)
    return ScanQueuedOut(scan_id=scan.id, status="queued")


@router.get("/{repo_id}/scans", response_model=list[ScanHistoryOut])
def list_repo_scans(repo_id: int, limit: int = 50, db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[dict]:
    owned_repo(db, repo_id, user)
    safe_limit = min(max(limit, 1), 100)
    scans = db.scalars(select(Scan).where(Scan.repo_id == repo_id).order_by(desc(Scan.id)).limit(safe_limit)).all()
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
