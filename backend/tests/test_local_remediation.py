import hashlib
import os
import subprocess
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core import scan_paths
from app.core.config import settings
from app.db.models import FindingType, Repo
from app.db.base import Base
from app.db.models import Finding, FindingStatus, Scan, ScanStatus, ScanTrigger, User
from app.api.findings import create_fix, _read_finding_file
from app.ai.models import Finding as ScannerFinding
from app.ai.fix import _safe_fallback
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.scanners.deps import DependencyScanResult
from app.services.fix_validation import validate_fix_candidate
from app.services.gitleaks import SecretScanResult
from app.services.local_remediation import requirements_candidate
from app.core.scan_paths import ScanPathError, validate_scan_path


FINDING = {"ecosystem": "PyPI", "package": "requests", "installed_version": "2.19.1", "fixed_version": "2.32.4"}


@pytest.mark.parametrize("content", ["requests>=2.19.1\n", "requests==2.19.1\nother @ https://example.invalid/a\n", "requests==2.19.1\nrequests==2.19.1\n"])
def test_local_candidate_refuses_ambiguous_manifests(content):
    assert requirements_candidate("requirements.txt", content, FINDING) is None


def test_local_candidate_is_single_advisory_backed_pin():
    assert requirements_candidate("requirements.txt", "requests==2.19.1\n", FINDING) == "requests==2.32.4\n"
    assert requirements_candidate("requirements.txt", "requests==2.19.1\n", {**FINDING, "fixed_version": None}) is None
    assert requirements_candidate("package.json", "requests==2.19.1\n", FINDING) is None


def test_local_validation_uses_copy_rejects_stale_and_preserves_original(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    root.mkdir()
    checkout = root / "repo"
    checkout.mkdir()
    target = checkout / "requirements.txt"
    original = "requests==2.19.1\n"
    target.write_bytes(original.encode("utf-8"))
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=root))
    monkeypatch.setenv("REPOGUARD_LOCAL_SCAN_ENABLED", "true")
    finding = SimpleNamespace(type=FindingType.dependency, file_path="requirements.txt", rule_id="TEST", advisory_id="TEST", aliases=[], **FINDING)
    fix = SimpleNamespace(target_file="requirements.txt", base_hash=hashlib.sha256(target.read_bytes()).hexdigest(), edits=[{"file_path": "requirements.txt", "new_content": "requests==2.32.4\n"}])
    before = {"package": "requests", "ecosystem": "PyPI", "installed_version": "2.19.1", "advisory_id": "TEST", "aliases": []}

    def deps(path):
        content = (path / "requirements.txt").read_text(encoding="utf-8")
        return DependencyScanResult([before] if "2.19.1" in content else [], "completed")

    with patch("app.services.fix_validation.scan_repository_secrets", return_value=SecretScanResult([], "empty", "gitleaks")), patch("app.services.fix_validation.scan_dependencies_with_status", side_effect=deps):
        result = validate_fix_candidate(Repo(local_path=str(checkout), full_name="local/test", default_branch="main"), finding, fix)
        assert result["security_rescan"] == "passed"
        assert result["tests"] == "not_run"
        assert target.read_text(encoding="utf-8") == original
        fix.base_hash = "0" * 64
        assert validate_fix_candidate(Repo(local_path=str(checkout), full_name="local/test", default_branch="main"), finding, fix)["security_rescan"] == "not_run"
    assert list(root.iterdir()) == [checkout]


def test_local_proposal_rejects_model_changes_outside_recorded_pin():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = User(email="owner@example.invalid", password_hash="synthetic")
        db.add(user)
        db.flush()
        repo = Repo(owner_id=user.id, local_path="/synthetic", full_name="local/example", default_branch="main")
        db.add(repo)
        db.flush()
        scan = Scan(repo_id=repo.id, trigger=ScanTrigger.manual, status=ScanStatus.done)
        db.add(scan)
        db.flush()
        finding = Finding(scan_id=scan.id, repo_id=repo.id, fingerprint="synthetic", type=FindingType.dependency, rule_id="TEST", title="Synthetic dependency", severity=None, scanner="osv", file_path="requirements.txt", advisory_id="TEST", confidence=0.9, status=FindingStatus.open, owasp_ids=[], asvs_ids=[], aliases=[], references=[], **FINDING)
        db.add(finding)
        db.commit()
        unsafe = {"patch": "synthetic diff", "edits": [{"file_path": "requirements.txt", "new_content": "requests==2.32.4\nother==1.0\n"}]}
        with patch("app.api.findings._read_finding_file", return_value=("requests==2.19.1\n", "0" * 64)), patch("app.api.findings.generate_fix", return_value=unsafe):
            result = create_fix(finding.id, db, user)
        assert result.patch is None
        assert result.status == "generated"
        assert result.validation.security_rescan == "not_run"
        safe = _safe_fallback(FINDING, "synthetic")
        safe.update({"patch": "synthetic diff", "edits": [{"file_path": "requirements.txt", "new_content": "requests==2.32.4\n"}], "target_file": "requirements.txt", "tier": "pr_review", "status": "pending_review", "failure_category": None})
        with patch("app.api.findings._read_finding_file", return_value=("requests==2.19.1\r\n", "0" * 64)), patch("app.api.findings.generate_fix", return_value=safe):
            result = create_fix(finding.id, db, user)
        assert result.status == "pending_review"
        assert result.edits[0].new_content == "requests==2.32.4\r\n"
        assert "+requests==2.32.4\r\n" in result.patch


def test_local_candidate_preserves_windows_line_endings():
    source = "requests==2.19.1\r\n"
    expected = requirements_candidate("requirements.txt", source, FINDING)
    assert expected == "requests==2.32.4\r\n"
    assert expected.replace("\r\n", "\n") == "requests==2.32.4\n"


def test_local_checkout_rejects_symlink_escape(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    root.mkdir()
    checkout = root / "repo"
    checkout.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (checkout / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("This account cannot create symbolic links")
        result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(checkout / "escape"), str(outside)], capture_output=True, check=False)
        if result.returncode:
            pytest.skip("This Windows account cannot create a symbolic link or junction")
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=root))
    with pytest.raises(ScanPathError):
        validate_scan_path(checkout)


def test_local_source_redacts_working_tree_secret_before_model(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    root.mkdir()
    checkout = root / "repo"
    checkout.mkdir()
    synthetic = "synthetic-secret-only"
    (checkout / "requirements.txt").write_text(f"requests==2.19.1\ntoken={synthetic}\n", encoding="utf-8")
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=root))
    monkeypatch.setenv("REPOGUARD_LOCAL_SCAN_ENABLED", "true")
    finding = ScannerFinding(file="requirements.txt", line=2, start_line=2, end_line=2, secret=synthetic, rule_id="synthetic")
    with patch("app.api.findings.scan_repository_secrets", return_value=SecretScanResult([finding], "completed", "gitleaks")) as scanner:
        source, _ = _read_finding_file(Repo(local_path=str(checkout), full_name="local/test", default_branch="main"), "requirements.txt")
    assert synthetic not in source
    assert "[REDACTED]" in source
    assert scanner.call_args.kwargs["working_tree"] is True
