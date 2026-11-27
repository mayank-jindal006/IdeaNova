from fastapi import BackgroundTasks
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.dashboard import summary
from app.api.findings import get_finding, list_findings
from app.api.repos import create_repo, get_repo, list_repo_scans, list_repos, queue_scan
from app.api.scans import get_scan, list_scan_findings
from app.db.base import Base
from app.db.models import Finding, FindingStatus, FindingType, Repo, Scan, ScanStatus, ScanTrigger, User
from app.schemas import RepoCreate


def _db() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_persistent_repository_scan_findings_and_dashboard_contracts():
    db = _db()
    user = User(email="owner@example.test", password_hash="fixture")
    db.add(user); db.commit()
    repo = create_repo(RepoCreate(full_name="owner/repo", default_branch="main"), db, user)
    assert repo.full_name == "owner/repo"
    assert repo.source_type == "github"
    assert list_repos(db, user)[0]["id"] == repo.id
    assert get_repo(repo.id, db, user)["repo"]["default_branch"] == "main"

    queued = queue_scan(repo.id, BackgroundTasks(), db, user)
    scan = get_scan(queued.scan_id, db, user)
    assert scan.status == ScanStatus.queued
    scan.status = ScanStatus.done
    scan.scanner_status = {"secrets": {"status": "empty", "source": "gitleaks", "count": 0}, "dependencies": {"status": "completed", "source": "osv", "count": 1}}
    db.add(Finding(scan_id=scan.id, repo_id=repo.id, fingerprint="fixture", type=FindingType.dependency, rule_id="OSV-1", title="Unknown severity advisory", severity=None, scanner="osv", package="example", ecosystem="PyPI", installed_version="1.0.0", advisory_id="OSV-1", aliases=[], references=[], in_history_only=False, confidence=0.9, status=FindingStatus.open, owasp_ids=["A06:2021"], asvs_ids=["V14.2.1"]))
    db.commit()

    history = list_repo_scans(repo.id, db=db, user=user)
    assert history[0]["findings_count"] == 1
    assert history[0]["scanner_status"]["dependencies"]["status"] == "completed"
    findings = list_findings(repo.id, db=db, user=user)
    assert findings[0].severity is None
    assert list_scan_findings(scan.id, db=db, user=user)[0].advisory_id == "OSV-1"
    assert get_finding(findings[0].id, db, user)["finding"]["severity"] is None
    dashboard = summary(db, user)
    assert dashboard["totals"]["open_findings"] == 1
    assert dashboard["severity_counts"]["critical"] == 0
    db.close()
