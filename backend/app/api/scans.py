from typing import Literal

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
def list_scan_findings(
    scan_id: int,
    limit: int = 200,
    offset: int = 0,
    sort_by: Literal["created_at", "severity"] = "created_at",
    sort_order: Literal["asc", "desc"] = "desc",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> list[Finding]:
    if not db.scalar(select(Scan).join(Repo).where(Scan.id == scan_id, Repo.owner_id == user.id)):
        raise HTTPException(404, "Scan not found")
    safe_limit = min(max(limit, 1), 500)
    safe_offset = max(offset, 0)
    sort_column = {"created_at": Finding.created_at, "severity": Finding.severity}[sort_by]
    sort_expression = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    return db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(sort_expression, Finding.id.desc())
        .offset(safe_offset)
        .limit(safe_limit)
    ).all()
