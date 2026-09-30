from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.errors import APIError
from app.github_client.client import cleanup_clone, clone_repo, commit_changes, create_branch, create_pull_request, get_default_branch, verify_webhook_signature
from app.models import Feedback, FeedbackVerdict, Finding, FindingStatus, Fix, FixStatus, Repo, RepoScore, Scan, ScanStatus, ScanTrigger
from app.schemas import FeedbackCreate, FindingOut, FixOut, RepoCreate, RepoOut, ScanCreated, ScanOut
from app.services.scans import run_scan

router = APIRouter(prefix="/api")


def _repo_or_404(repo_id: int, db: Session) -> Repo:
    repo = db.get(Repo, repo_id)
    if not repo:
        raise APIError(404, "REPO_NOT_FOUND", "Repository was not found")
    return repo


def _finding_or_404(finding_id: int, db: Session) -> Finding:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise APIError(404, "FINDING_NOT_FOUND", "Finding was not found")
    return finding


def _latest_score(repo_id: int, db: Session):
    return db.scalar(select(RepoScore).where(RepoScore.repo_id == repo_id).order_by(RepoScore.computed_at.desc()))


@router.get("/repos")
def list_repos(db: Session = Depends(get_db)):
    result = []
    for repo in db.scalars(select(Repo).order_by(Repo.id)).all():
        data = RepoOut.model_validate(repo).model_dump(mode="json")
        score = _latest_score(repo.id, db)
        data["latest_score"] = None if not score else {"compliance_score": score.compliance_score, "risk_score": score.risk_score}
        result.append(data)
    return result


@router.post("/repos", response_model=RepoOut, status_code=201)
def create_repo(payload: RepoCreate, db: Session = Depends(get_db)):
    if db.scalar(select(Repo).where(Repo.full_name == payload.full_name)):
        raise APIError(409, "REPO_EXISTS", "Repository is already tracked")
    try:
        default_branch = get_default_branch(payload.full_name)
    except Exception as exc:
        raise APIError(502, "GITHUB_REPOSITORY_LOOKUP_FAILED", str(exc)) from exc
    repo = Repo(full_name=payload.full_name, default_branch=default_branch)
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


@router.post("/repos/{repo_id}/scan", response_model=ScanCreated, status_code=202)
def create_scan(repo_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    _repo_or_404(repo_id, db)
    scan = Scan(repo_id=repo_id, trigger=ScanTrigger.manual, status=ScanStatus.queued)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(run_scan, scan.id)
    return {"scan_id": scan.id, "status": scan.status.value}


@router.get("/repos/{repo_id}")
def get_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = _repo_or_404(repo_id, db)
    data = RepoOut.model_validate(repo).model_dump(mode="json")
    score = _latest_score(repo.id, db)
    data["latest_score"] = None if not score else {"id": score.id, "compliance_score": score.compliance_score, "control_results": score.control_results, "risk_score": score.risk_score, "risk_factors": score.risk_factors, "computed_at": score.computed_at}
    return data


@router.get("/repos/{repo_id}/findings", response_model=list[FindingOut])
def list_findings(repo_id: int, type: str | None = None, status: str | None = None, severity: str | None = None, db: Session = Depends(get_db)):
    _repo_or_404(repo_id, db)
    query = select(Finding).where(Finding.repo_id == repo_id)
    if type:
        query = query.where(Finding.type == type)
    if status:
        query = query.where(Finding.status == status)
    if severity:
        query = query.where(Finding.severity == severity)
    return db.scalars(query.order_by(Finding.created_at.desc())).all()


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = _finding_or_404(finding_id, db)
    data = FindingOut.model_validate(finding).model_dump(mode="json")
    fix = db.scalar(select(Fix).where(Fix.finding_id == finding.id).order_by(Fix.created_at.desc()))
    data["latest_fix"] = None if not fix else {"id": fix.id, "finding_id": fix.finding_id, "explanation": fix.explanation, "edits": fix.edits, "tier": fix.tier.value, "validation": fix.validation, "pr_url": fix.pr_url, "pr_number": fix.pr_number, "status": fix.status.value}
    data["rotation_checklist"] = _rotation_checklist(finding)
    return data


def _rotation_checklist(finding: Finding):
    if finding.type.value != "secret":
        return []
    try:
        from app.compliance.rotation import rotation_checklist
        return rotation_checklist(finding.rule_id)
    except ImportError:
        return []


@router.post("/findings/{finding_id}/fix", response_model=FixOut)
def generate_fix(finding_id: int, db: Session = Depends(get_db)):
    finding = _finding_or_404(finding_id, db)
    try:
        from app.ai.fix import generate_fix as ai_generate_fix
    except ImportError as exc:
        raise APIError(503, "AI_UNAVAILABLE", "AI fix module is not available") from exc
    clone_path = None
    try:
        clone_path = clone_repo(finding.repo.full_name)
        root = Path(clone_path).resolve()
        affected_file = (root / finding.file_path).resolve()
        if root not in affected_file.parents and affected_file != root:
            raise APIError(400, "INVALID_FINDING_PATH", "Finding file path is invalid")
        file_content = affected_file.read_text(encoding="utf-8") if affected_file.exists() else ""
        repo_files = [str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]
        generated = ai_generate_fix(FindingOut.model_validate(finding).model_dump(mode="json"), file_content, repo_files)
        required = {"finding_id", "explanation", "edits", "tier", "validation"}
        if set(generated) != required or generated["finding_id"] != finding.id:
            raise APIError(502, "INVALID_AI_FIX", "AI module returned a fix outside the contract")
        validation_ok = bool(generated["validation"].get("secret_removed")) and bool(generated["validation"].get("syntax_ok"))
        fix = Fix(finding_id=finding.id, explanation=generated["explanation"], edits=generated["edits"], tier=generated["tier"], validation=generated["validation"], status=FixStatus.generated if validation_ok else FixStatus.validation_failed)
        db.add(fix)
        finding.status = FindingStatus.fix_proposed
        db.commit()
        db.refresh(fix)
        generated["id"] = fix.id
        return generated
    except APIError:
        raise
    except Exception as exc:
        raise APIError(502, "FIX_GENERATION_FAILED", str(exc)) from exc
    finally:
        if clone_path:
            cleanup_clone(clone_path)


@router.post("/fixes/{fix_id}/open-pr")
def open_pr(fix_id: int, db: Session = Depends(get_db)):
    fix = db.get(Fix, fix_id)
    if not fix:
        raise APIError(404, "FIX_NOT_FOUND", "Fix was not found")
    if fix.tier.value == "flag_only" or not fix.edits:
        raise APIError(409, "FIX_NOT_APPLICABLE", "This fix cannot be opened as a pull request")
    finding, repo = fix.finding, fix.finding.repo
    branch = f"repoguard/fix-{finding.id}"
    try:
        create_branch(repo.full_name, branch, repo.default_branch)
    except Exception as exc:
        if getattr(exc, "status", None) != 422:
            raise APIError(502, "GITHUB_BRANCH_FAILED", str(exc)) from exc
    commit_changes(repo.full_name, branch, fix.edits, f"RepoGuard: fix {finding.title}")
    body = _pr_body(finding, fix)
    url, number = create_pull_request(repo.full_name, branch, repo.default_branch, f"RepoGuard: {finding.title}", body)
    fix.pr_url, fix.pr_number, fix.status = url, number, FixStatus.pr_opened
    finding.status = FindingStatus.pr_opened
    db.commit()
    return {"pr_url": url, "pr_number": number}


def _pr_body(finding: Finding, fix: Fix) -> str:
    explanation = fix.explanation
    return f"""## 🔐 RepoGuard: {finding.title}
**Severity:** {finding.severity.value} · **Rule:** {finding.rule_id} · **OWASP:** {finding.owasp_ids} · **ASVS:** {finding.asvs_ids}

### What was found
{explanation.get('what', '')}

### Why it's dangerous
{explanation.get('why_dangerous', '')}

### What this PR changes
{explanation.get('how_fixed', '')}

### ⚠️ Rotation required
{explanation.get('rotation_note', '')}
This PR removes the secret from the current code, but it remains in git history.
Revoke and rotate the credential before merging.

_Generated by RepoGuard. Review before merging. Nothing is merged automatically._"""


@router.post("/findings/{finding_id}/feedback", response_model=FindingOut)
def create_feedback(finding_id: int, payload: FeedbackCreate, db: Session = Depends(get_db)):
    finding = _finding_or_404(finding_id, db)
    db.add(Feedback(finding_id=finding.id, verdict=FeedbackVerdict(payload.verdict), note=payload.note))
    if payload.verdict == "false_positive":
        finding.status = FindingStatus.false_positive
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    repos = db.scalars(select(Repo).order_by(Repo.id)).all()
    severity_counts = {name: db.scalar(select(func.count()).select_from(Finding).where(Finding.severity == name, Finding.status.not_in([FindingStatus.fixed, FindingStatus.false_positive]))) or 0 for name in ("critical", "high", "medium", "low")}
    scores = []
    for repo in repos:
        score = _latest_score(repo.id, db)
        if score:
            scores.append({"repo_id": repo.id, "full_name": repo.full_name, "compliance_score": score.compliance_score, "risk_score": score.risk_score, "risk_factors": score.risk_factors})
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    trend = [{"date": row[0].date().isoformat(), "findings": row[1]} for row in db.execute(select(Finding.created_at, func.count(Finding.id)).where(Finding.created_at >= cutoff).group_by(Finding.created_at)).all()]
    return {"totals": {"repos": len(repos), "findings": db.scalar(select(func.count()).select_from(Finding)) or 0}, "severity_counts": severity_counts, "repo_scores": scores, "trend": trend}


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise APIError(404, "SCAN_NOT_FOUND", "Scan was not found")
    return scan


@router.post("/webhooks/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    payload = await request.body()
    if not verify_webhook_signature(payload, request.headers.get("X-Hub-Signature-256")):
        raise APIError(401, "INVALID_WEBHOOK_SIGNATURE", "Webhook signature verification failed")
    event = request.headers.get("X-GitHub-Event")
    body = await request.json()
    if event == "push":
        full_name = body.get("repository", {}).get("full_name")
        repo = db.scalar(select(Repo).where(Repo.full_name == full_name))
        if repo:
            scan = Scan(repo_id=repo.id, trigger=ScanTrigger.push, commit_sha=body.get("after"), status=ScanStatus.queued)
            db.add(scan)
            db.commit()
            background_tasks.add_task(run_scan, scan.id)
    return {"ok": True}
