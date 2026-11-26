from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.compliance.score import compute_compliance, map_controls
from app.core.process_env import subprocess_environment
from app.db.models import Finding, FindingStatus, Repo, RepoScore, Scan, ScanStatus, ScanTrigger
from app.github_client.client import clone_repo, repo_signals
from app.risk.heuristic import compute_risk
from app.scanners.deps import scan_dependencies_with_status
from app.scanners.secrets import secret_scan_to_persistence
from app.services.gitleaks import scan_repository_secrets

logger = logging.getLogger(__name__)


def _remove_readonly(function: Callable[[str], None], path: str, error: OSError) -> None:
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        function(path)
    except OSError:
        raise error


def _remove_checkout(repo_path: str) -> None:
    shutil.rmtree(repo_path, onexc=_remove_readonly)


def _fingerprint(finding: dict) -> str:
    source = finding["secret_hash"] if finding["type"] == "secret" else f"{finding['package']}:{finding['installed_version']}"
    return hashlib.sha256(f"{finding['rule_id']}:{finding.get('file_path')}:{source}".encode()).hexdigest()


def run_scan(db: Session, scan_id: int) -> None:
    scan = db.get(Scan, scan_id)
    if not scan:
        return
    scan.status, scan.started_at = ScanStatus.running, datetime.now(timezone.utc)
    db.commit()
    repo_path: str | None = None
    try:
        repo = db.get(Repo, scan.repo_id)
        if not repo:
            raise RuntimeError("Repository no longer exists")
        pushed_commit = scan.commit_sha if scan.trigger == ScanTrigger.push else None
        pushed_ref = scan.ref if scan.trigger == ScanTrigger.push else None
        if scan.trigger == ScanTrigger.push and (not pushed_commit or not pushed_ref):
            raise RuntimeError("Push scan is missing its validated ref or commit")
        repo_path = clone_repo(repo.full_name, commit_sha=pushed_commit, ref=pushed_ref)
        scanned_commit = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            env=subprocess_environment(),
        ).stdout.strip()
        if pushed_commit and scanned_commit != pushed_commit:
            raise RuntimeError("Checkout does not match the pushed commit")
        scan.commit_sha = scanned_commit
        secret_scan = scan_repository_secrets(repo_path, include_history=True)
        dependency_scan = scan_dependencies_with_status(repo_path)
        findings = secret_scan_to_persistence(secret_scan) + _dependency_findings_for_persistence(dependency_scan.findings)
        scan.scanner_status = {
            "secrets": {
                "status": secret_scan.status,
                "source": secret_scan.source,
                "reason": secret_scan.reason,
                "count": len(secret_scan.findings),
            },
            "dependencies": {
                "status": dependency_scan.status,
                "source": "osv",
                "reason": dependency_scan.reason,
                "count": len(dependency_scan.findings),
                "dependencies_queried": dependency_scan.dependencies_queried,
            },
        }
        signals = repo_signals(repo_path)
        signals["historical_secret_count"] = sum(1 for finding in findings if finding["type"] == "secret" and finding["in_history_only"])
        for payload in findings:
            payload["owasp_ids"], payload["asvs_ids"] = map_controls(payload)
            fingerprint = _fingerprint(payload)
            existing = db.scalar(select(Finding).where(Finding.repo_id == repo.id, Finding.fingerprint == fingerprint))
            if existing:
                existing.scan_id = scan.id
                if existing.status != FindingStatus.false_positive:
                    existing.status = FindingStatus.needs_rotation if existing.type.value == "secret" else FindingStatus.open
                continue
            db.add(Finding(scan_id=scan.id, repo_id=repo.id, fingerprint=fingerprint, **payload))
        db.flush()
        finding_dicts = [_finding_dict(finding) for finding in db.scalars(select(Finding).where(Finding.repo_id == repo.id)).all()]
        compliance = compute_compliance(finding_dicts)
        risk = compute_risk(signals, finding_dicts)
        db.add(RepoScore(repo_id=repo.id, scan_id=scan.id, compliance_score=compliance["score"], control_results=compliance["control_results"], risk_score=risk["score"], risk_factors=risk["factors"]))
        scan.status, scan.finished_at, repo.last_scanned_at = ScanStatus.done, datetime.now(timezone.utc), datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            # Exceptions from clone/scanner subprocesses can contain a credential-bearing
            # clone URL or source content. Persist only a safe, stable failure message.
            scan.status, scan.error, scan.finished_at = ScanStatus.failed, "Repository scan failed", datetime.now(timezone.utc)
            db.commit()
    finally:
        if repo_path:
            try:
                _remove_checkout(repo_path)
            except OSError:
                logger.error("Repository checkout cleanup failed scan_id=%s", scan_id)
                db.rollback()
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = ScanStatus.failed
                    scan.error = "Repository scan cleanup failed"
                    scan.finished_at = datetime.now(timezone.utc)
                    db.commit()


def _finding_dict(finding: Finding) -> dict:
    return {"id": finding.id, "type": finding.type.value, "rule_id": finding.rule_id, "title": finding.title, "severity": finding.severity.value if finding.severity else None, "scanner": finding.scanner, "file_path": finding.file_path, "line": finding.line, "commit_sha": finding.commit_sha, "secret_masked": finding.secret_masked, "package": finding.package, "ecosystem": finding.ecosystem, "installed_version": finding.installed_version, "affected_versions": finding.affected_versions, "fixed_version": finding.fixed_version, "advisory_id": finding.advisory_id, "aliases": finding.aliases, "references": finding.references, "cvss_score": finding.cvss_score, "in_history_only": finding.in_history_only, "confidence": finding.confidence, "status": finding.status.value, "owasp_ids": finding.owasp_ids, "asvs_ids": finding.asvs_ids}


def _dependency_findings_for_persistence(findings: list[dict]) -> list[dict]:
    """Map canonical OSV findings to ORM field names without inventing severity."""
    return [{
        "type": "dependency",
        "scanner": finding["scanner"],
        "rule_id": finding["rule_id"],
        "title": finding["description"],
        "severity": finding["severity"],
        "file_path": finding["file"],
        "line": finding["line"],
        "commit_sha": None,
        "secret_masked": None,
        "secret_hash": None,
        "package": finding["package"],
        "ecosystem": finding["ecosystem"],
        "installed_version": finding["installed_version"],
        "affected_versions": finding["affected_versions"],
        "fixed_version": finding["fixed_version"],
        "advisory_id": finding["advisory_id"],
        "aliases": finding["aliases"],
        "references": finding["references"],
        "cvss_score": finding["cvss_score"],
        "in_history_only": False,
        "confidence": 0.9,
        "status": "open",
    } for finding in findings]
