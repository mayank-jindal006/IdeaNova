import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.session import SessionLocal
from app.agent_log import record_agent_run
from app.github_client.client import cleanup_clone, clone_repo, clone_repo_ref, current_commit_sha, repo_signals
from app.models import Finding, FindingStatus, Repo, RepoScore, Scan, ScanStatus
from app.scanners.deps import scan_dependencies
from app.scanners.secrets import scan_secrets

logger = logging.getLogger(__name__)


def _controls(finding: dict) -> tuple[list[str], list[str]]:
    try:
        from app.compliance.score import map_controls
        return map_controls(finding)
    except ImportError:
        logger.warning("Compliance module is not available; findings will await mapping")
        return [], []


def _score(repo_id: int, scan_id: int, findings: list[dict], signals: dict, db) -> None:
    try:
        from app.compliance.score import compute_compliance
        from app.risk.heuristic import compute_risk
    except ImportError:
        logger.warning("Compliance/risk modules are not available; score was not stored")
        return
    compliance = compute_compliance(findings)
    risk = compute_risk(signals, findings)
    db.add(RepoScore(repo_id=repo_id, scan_id=scan_id, compliance_score=compliance["score"], control_results=compliance["control_results"], risk_score=risk["score"], risk_factors=risk["factors"]))


def run_scan(scan_id: int) -> None:
    db = SessionLocal()
    clone_path = None
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        repo = db.get(Repo, scan.repo_id)
        scan.status = ScanStatus.running
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        clone_path = clone_repo_ref(repo.full_name, scan.commit_sha) if scan.trigger.value == "pull_request" and scan.commit_sha else clone_repo(repo.full_name)
        findings = scan_secrets(clone_path) + scan_dependencies(clone_path)
        scan.commit_sha = current_commit_sha(clone_path)
        head_secret_fingerprints = {item["fingerprint"] for item in findings if item["type"] == "secret" and not item["in_history_only"]}
        history_secret_fingerprints = {item["fingerprint"] for item in findings if item["type"] == "secret" and item["in_history_only"]}
        new_finding_ids = []
        for item in findings:
            item["owasp_ids"], item["asvs_ids"] = _controls(item)
            existing = db.scalar(select(Finding).where(Finding.repo_id == repo.id, Finding.fingerprint == item["fingerprint"]))
            if existing:
                if existing.status != FindingStatus.false_positive:
                    for key, value in item.items():
                        if key != "fingerprint":
                            setattr(existing, key, value)
                    existing.scan_id = scan.id
                continue
            finding = Finding(scan_id=scan.id, repo_id=repo.id, **item)
            db.add(finding)
            db.flush()
            new_finding_ids.append(finding.id)
        for existing in db.scalars(select(Finding).where(Finding.repo_id == repo.id, Finding.type == "secret")).all():
            if existing.status != FindingStatus.false_positive and existing.fingerprint in history_secret_fingerprints and existing.fingerprint not in head_secret_fingerprints:
                existing.in_history_only = True
                existing.status = FindingStatus.needs_rotation
        db.flush()
        persisted = [dict(item) for item in findings]
        _score(repo.id, scan.id, persisted, repo_signals(clone_path, findings), db)
        scan.status = ScanStatus.done
        scan.finished_at = datetime.now(timezone.utc)
        repo.last_scanned_at = scan.finished_at
        db.commit()
        if repo.auto_fix_enabled and new_finding_ids:
            _handle_new_findings(db, repo.id, new_finding_ids)
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.failed
            scan.error = str(exc)
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        if clone_path:
            cleanup_clone(clone_path)
        db.close()


def _handle_new_findings(db, repo_id: int, new_finding_ids: list[int]) -> None:
    """Delegate to Saina's optional agent module without owning its business logic."""
    try:
        from app import agent
        agent.handle_new_findings(db, repo_id, new_finding_ids)
        db.commit()
    except (ImportError, AttributeError) as exc:
        record_agent_run(db, repo_id, step="error", status="failed", detail=f"Agent handler unavailable: {exc}")
        db.commit()
    except Exception as exc:
        logger.exception("Agent failed while handling new findings for repo %s", repo_id)
        record_agent_run(db, repo_id, step="error", status="failed", detail=f"Agent handler failed: {exc}")
        db.commit()
