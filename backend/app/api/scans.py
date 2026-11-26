from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from sqlalchemy import desc, select

from app.db.models import Finding, Repo, Scan, User
from app.auth import current_user
from app.schemas import FindingOut
from app.db.session import get_db
from app.schemas import ScanOut

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> Scan:
    scan = db.scalar(select(Scan).join(Repo).where(Scan.id == scan_id, Repo.owner_id == user.id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
def list_scan_findings(scan_id: int, limit: int = 200, db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[Finding]:
    if not db.scalar(select(Scan).join(Repo).where(Scan.id == scan_id, Repo.owner_id == user.id)):
        raise HTTPException(404, "Scan not found")
    return db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(desc(Finding.created_at)).limit(min(max(limit, 1), 500))).all()
