from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.repos import _background_scan
from app.db.models import Repo, Scan, ScanStatus, ScanTrigger
from app.db.session import get_db
from app.github_client.client import verify_webhook_signature

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    payload_bytes = await request.body()
    if not verify_webhook_signature(payload_bytes, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(401, "Webhook signature is invalid")
    payload = await request.json()
    if request.headers.get("X-GitHub-Event") != "push":
        return {}
    full_name = payload.get("repository", {}).get("full_name")
    repo = db.scalar(select(Repo).where(Repo.full_name == full_name))
    if not repo:
        return {}
    scan = Scan(repo_id=repo.id, trigger=ScanTrigger.push, commit_sha=payload.get("after"), status=ScanStatus.queued)
    db.add(scan)
    db.commit()
    background_tasks.add_task(_background_scan, scan.id)
    return {}
