from __future__ import annotations

import json
import re

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.repos import _background_scan
from app.db.models import Repo, Scan, ScanStatus, ScanTrigger
from app.db.session import get_db
from app.github_client.client import is_valid_github_full_name, is_valid_github_push_ref, verify_webhook_signature

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_ZERO_COMMIT_SHA = "0" * 40


def _invalid_payload() -> HTTPException:
    return HTTPException(400, "Webhook payload is invalid")


@router.post("/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    payload_bytes = await request.body()
    if not verify_webhook_signature(payload_bytes, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(401, "Webhook signature is invalid")
    if request.headers.get("X-GitHub-Event") != "push":
        return {}
    try:
        payload = json.loads(payload_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _invalid_payload() from None
    if not isinstance(payload, dict):
        raise _invalid_payload()

    repository = payload.get("repository")
    full_name = repository.get("full_name") if isinstance(repository, dict) else None
    ref = payload.get("ref")
    commit_sha = payload.get("after")
    deleted = payload.get("deleted")
    if (
        not is_valid_github_full_name(full_name)
        or not is_valid_github_push_ref(ref)
        or not isinstance(commit_sha, str)
        or not _COMMIT_SHA.fullmatch(commit_sha)
        or not isinstance(deleted, bool)
        or (deleted and commit_sha != _ZERO_COMMIT_SHA)
        or (not deleted and commit_sha == _ZERO_COMMIT_SHA)
    ):
        raise _invalid_payload()
    if deleted:
        return {"queued": 0, "deleted": True}

    repos = db.scalars(
        select(Repo)
        .where(func.lower(Repo.full_name) == full_name.lower())
        .order_by(Repo.id)
        .with_for_update()
    ).all()
    queued_scans: list[Scan] = []
    for repo in repos:
        duplicate = db.scalar(select(Scan.id).where(
            Scan.repo_id == repo.id,
            Scan.trigger == ScanTrigger.push,
            Scan.commit_sha == commit_sha,
        ))
        if duplicate is not None:
            continue
        scan = Scan(
            repo_id=repo.id,
            trigger=ScanTrigger.push,
            ref=ref,
            commit_sha=commit_sha,
            status=ScanStatus.queued,
        )
        db.add(scan)
        queued_scans.append(scan)

    if queued_scans:
        db.commit()
        for scan in queued_scans:
            background_tasks.add_task(_background_scan, scan.id)
    return {"queued": len(queued_scans)}
