import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.ai.models import Finding
from app.db.base import Base
from app.db.models import Finding as DbFinding, Repo, Scan, ScanStatus, ScanTrigger
from app.scanners.deps import Dependency, DependencyScanResult, _finding, _severity, discover_dependencies, scan_dependencies_with_status
from app.scanners.secrets import scan_secrets, secret_scan_to_persistence
from app.services.gitleaks import SecretScanResult, scan_repository_secrets
from app.services.scan_service import _dependency_findings_for_persistence, run_scan

_DUMMY_SECRET = "ghp_a8K4mQ2zV7cN9xL3pR6tY1wB5dF0hJ4sG8"


def _write_report(command, report, returncode=0, **_kwargs):
    report_path = Path(command[command.index("--report-path") + 1])
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return subprocess.CompletedProcess(command, returncode)


def _repo_with_secret(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        f'token="{_DUMMY_SECRET}"\n',
        encoding="utf-8",
    )
    return repo


def _gitleaks_report(secret=_DUMMY_SECRET):
    return [{
        "File": "app.py",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 10,
        "EndColumn": 47,
        "Secret": secret,
        "Match": f'token = "{secret}"',
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "Tags": ["key", "API", "generic"],
    }]


def test_gitleaks_binary_report_is_parsed_and_preserves_line_metadata(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", side_effect=["gitleaks.exe"]), patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=lambda command, **kwargs: _write_report(command, _gitleaks_report(), returncode=1, **kwargs),
    ) as run:
        result = scan_repository_secrets(repo)

    assert result.status == "completed"
    assert result.source == "gitleaks"
    assert result.findings[0].secret == _DUMMY_SECRET
    assert result.findings[0].line == 1
    assert result.findings[0].start_line == 1
    assert result.findings[0].rule_id == "generic-api-key"
    assert run.call_args.args[0][1:3] == ["detect", "--source"]
    assert run.call_args.args[0][run.call_args.args[0].index("--exit-code") + 1] == "1"


def test_gitleaks_discovery_prefers_configured_environment_path(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    binary = tmp_path / "configured-gitleaks.exe"
    binary.write_bytes(b"test binary placeholder")
    monkeypatch.setenv("GITLEAKS_BIN", str(binary))
    with patch(
        "app.services.gitleaks.shutil.which",
        side_effect=AssertionError("PATH lookup should not override GITLEAKS_BIN"),
    ), patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=lambda command, **kwargs: _write_report(command, [], **kwargs),
    ) as run:
        result = scan_repository_secrets(repo)
    assert result.status == "empty"
    assert result.source == "gitleaks"
    assert run.call_args.args[0][0] == str(binary.resolve())


def test_gitleaks_discovery_uses_path_when_environment_is_unset(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch(
        "app.services.gitleaks.shutil.which",
        side_effect=[None, "C:\\tools\\gitleaks.exe"],
    ) as which, patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=lambda command, **kwargs: _write_report(command, [], **kwargs),
    ) as run:
        result = scan_repository_secrets(repo)
    assert result.status == "empty"
    assert result.source == "gitleaks"
    assert which.call_args_list[0].args == ("gitleaks",)
    assert which.call_args_list[1].args == ("gitleaks.exe",)
    assert run.call_args.args[0][0] == "C:\\tools\\gitleaks.exe"


def test_gitleaks_empty_report_is_labeled_empty(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", return_value="gitleaks"), patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=lambda command, **kwargs: _write_report(command, [], **kwargs),
    ):
        result = scan_repository_secrets(repo)
    assert result.status == "empty"
    assert result.source == "gitleaks"
    assert result.findings == []


def test_configured_missing_binary_uses_labeled_fallback(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.setenv("GITLEAKS_BIN", str(tmp_path / "missing-gitleaks.exe"))
    with patch("app.services.gitleaks.shutil.which") as which:
        result = scan_repository_secrets(repo)
    which.assert_not_called()
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_configured_binary_unavailable"
    assert result.findings


def test_gitleaks_invalid_report_uses_labeled_fallback(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)

    def write_bad_report(command, **kwargs):
        Path(command[command.index("--report-path") + 1]).write_text("not-json", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    with patch("app.services.gitleaks.shutil.which", return_value="gitleaks"), patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=write_bad_report,
    ):
        result = scan_repository_secrets(repo)
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_invalid_report"
    assert result.findings


def test_gitleaks_missing_report_uses_labeled_fallback(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", return_value="gitleaks"), patch(
        "app.services.gitleaks.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0),
    ):
        result = scan_repository_secrets(repo)
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_report_missing"


def test_gitleaks_missing_binary_uses_labeled_fallback(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", return_value=None):
        result = scan_repository_secrets(repo)
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_binary_unavailable"


def test_gitleaks_timeout_uses_labeled_fallback(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", return_value="gitleaks"), patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=subprocess.TimeoutExpired("gitleaks", 1),
    ):
        result = scan_repository_secrets(repo)
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_timeout"


def test_gitleaks_unexpected_exit_uses_labeled_fallback(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", return_value="gitleaks"), patch(
        "app.services.gitleaks.subprocess.run",
        return_value=subprocess.CompletedProcess([], 2),
    ):
        result = scan_repository_secrets(repo)
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_nonzero_exit"


def test_gitleaks_exit_one_with_empty_report_is_not_reported_as_clean(tmp_path, monkeypatch):
    repo = _repo_with_secret(tmp_path)
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    with patch("app.services.gitleaks.shutil.which", return_value="gitleaks"), patch(
        "app.services.gitleaks.subprocess.run",
        side_effect=lambda command, **kwargs: _write_report(command, [], returncode=1, **kwargs),
    ):
        result = scan_repository_secrets(repo)
    assert result.status == "fallback"
    assert result.source == "regex_fallback"
    assert result.reason == "gitleaks_exit_code_inconsistent"
    assert result.findings


def test_dependency_discovery_prefers_lockfile_versions(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/example": {"version": "1.2.3"}}}), encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"unresolved": "^1.0.0"}}), encoding="utf-8")
    dependencies = discover_dependencies(tmp_path)
    assert [(item.name, item.version, item.ecosystem) for item in dependencies] == [("example", "1.2.3", "npm")]


def test_osv_response_normalizes_vulnerability(tmp_path):
    (tmp_path / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    response = Mock()
    response.json.return_value = {"results": [{"vulns": [{"id": "OSV-TEST-1", "modified": "2026-01-01T00:00:00Z"}]}]}
    response.raise_for_status.return_value = None
    detail = Mock()
    detail.json.return_value = {
        "id": "OSV-TEST-1",
        "summary": "Test vulnerability",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"name": "example", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
        }],
        "references": [{"url": "https://example.invalid/advisory"}],
    }
    detail.raise_for_status.return_value = None
    with patch("app.scanners.deps.httpx.post", return_value=response), patch(
        "app.scanners.deps.httpx.get",
        return_value=detail,
    ) as get:
        result = scan_dependencies_with_status(tmp_path)
    assert result.status == "completed"
    assert result.findings[0]["rule_id"] == "OSV-TEST-1"
    assert result.findings[0]["advisory_id"] == "OSV-TEST-1"
    assert result.findings[0]["fixed_version"] == "1.0.1"
    assert result.findings[0]["affected_versions"] == "< 1.0.1"
    assert result.findings[0]["severity"] == "high"
    assert get.call_args.args[0] == "https://api.osv.dev/v1/vulns/OSV-TEST-1"


def test_osv_finding_preserves_advisory_package_range_and_references(tmp_path):
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture", "version": "1.0.0"},
            "node_modules/source-map-js": {"version": "1.2.1"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile), encoding="utf-8")
    vulnerability = {
        "id": "GHSA-test-1234",
        "aliases": ["CVE-2026-12345"],
        "summary": "Synthetic source map advisory",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"name": "source-map-js", "ecosystem": "npm"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.2"}],
            }],
        }],
        "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
    }
    response = Mock()
    response.json.return_value = {"results": [{"vulns": [{"id": vulnerability["id"], "modified": "2026-01-01T00:00:00Z"}]}]}
    response.raise_for_status.return_value = None
    detail = Mock()
    detail.json.return_value = vulnerability
    detail.raise_for_status.return_value = None

    with patch("app.scanners.deps.httpx.post", return_value=response) as post, patch(
        "app.scanners.deps.httpx.get",
        return_value=detail,
    ):
        result = scan_dependencies_with_status(tmp_path)

    finding = result.findings[0]
    assert result.status == "completed"
    assert post.call_args.kwargs["json"]["queries"][0] == {
        "package": {"name": "source-map-js", "ecosystem": "npm"},
        "version": "1.2.1",
    }
    assert finding["advisory_id"] == "GHSA-test-1234"
    assert finding["aliases"] == ["CVE-2026-12345"]
    assert finding["package"] == "source-map-js"
    assert finding["ecosystem"] == "npm"
    assert finding["installed_version"] == "1.2.1"
    assert finding["affected_versions"] == ">= 1.0.0, < 1.2.2"
    assert finding["fixed_version"] == "1.2.2"
    assert finding["references"] == ["https://example.invalid/advisory"]
    assert finding["severity"] == "high"
    assert finding["cvss_score"] is None


def test_osv_missing_advisory_id_is_not_fabricated():
    dependency = Dependency("example", "1.0.0", "npm", "package-lock.json")
    assert _finding({"summary": "Missing identifier"}, dependency) is None


def test_osv_severity_uses_database_label_or_numeric_cvss_only():
    assert _severity({"database_specific": {"severity": "HIGH"}}) == "high"
    assert _severity({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}) == "high"
    assert _severity({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
    }) is None
    assert _severity({}) is None


def test_osv_unavailable_invalid_and_no_manifest_states(tmp_path):
    assert scan_dependencies_with_status(tmp_path).status == "skipped"
    (tmp_path / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    with patch("app.scanners.deps.httpx.post", side_effect=httpx.TimeoutException("timeout")):
        assert scan_dependencies_with_status(tmp_path).reason == "osv_timeout"
    response = Mock()
    response.json.return_value = {"results": []}
    response.raise_for_status.return_value = None
    with patch("app.scanners.deps.httpx.post", return_value=response):
        assert scan_dependencies_with_status(tmp_path).reason == "osv_invalid_response"


def test_secret_persistence_adapter_redacts_raw_material_and_preserves_source():
    raw_secret = "ghp_abcdef0123456789abcdef0123456789abcd"
    finding = Finding(
        file="app.py", line=5, secret=raw_secret, match=raw_secret, rule_id="github-pat"
    )
    records = secret_scan_to_persistence(SecretScanResult([finding], "fallback", "regex_fallback", "gitleaks_binary_unavailable"))

    assert records[0]["scanner"] == "regex_fallback"
    assert records[0]["secret_masked"] != raw_secret
    assert raw_secret not in str(records[0])
    assert records[0]["secret_hash"]


def test_legacy_secret_adapter_delegates_to_canonical_scanner(tmp_path):
    finding = Finding(
        file="app.py", line=1, secret="token-value-1234", rule_id="generic-api-key"
    )
    with patch("app.scanners.secrets.scan_repository_secrets", return_value=SecretScanResult([finding], "completed", "gitleaks")) as scan:
        records = scan_secrets(str(tmp_path))

    scan.assert_called_once_with(str(tmp_path), True)
    assert records[0]["scanner"] == "gitleaks"


def test_osv_persistence_payload_and_orm_model_preserve_unknown_severity():
    canonical = {
        "type": "dependency", "scanner": "osv", "file": "requirements.txt", "line": None,
        "description": "An advisory with no supported severity", "rule_id": "OSV-TEST-UNKNOWN",
        "advisory_id": "OSV-TEST-UNKNOWN", "aliases": ["CVE-2026-0001"], "severity": None,
        "cvss_score": None, "package": "example", "ecosystem": "PyPI", "installed_version": "1.0.0",
        "affected_versions": "< 1.0.1", "fixed_version": "1.0.1", "references": ["https://example.invalid/advisory"],
    }
    payload = _dependency_findings_for_persistence([canonical])[0]
    record = DbFinding(scan_id=1, repo_id=1, fingerprint="fixture", **payload)

    assert record.severity is None
    assert record.scanner == "osv"
    assert record.advisory_id == "OSV-TEST-UNKNOWN"
    assert record.aliases == ["CVE-2026-0001"]
    assert record.references == ["https://example.invalid/advisory"]


def test_queued_scan_uses_canonical_gitleaks_and_persists_scanner_status(tmp_path):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = Session(engine)
    repo = Repo(full_name="owner/repo", default_branch="main")
    db.add(repo)
    db.commit()
    scan = Scan(repo_id=repo.id, trigger=ScanTrigger.manual, status=ScanStatus.queued)
    db.add(scan)
    db.commit()

    secret = Finding(file="config.py", line=1, secret="token-value-1234", rule_id="generic-api-key")
    dependency = {
        "type": "dependency", "scanner": "osv", "file": "requirements.txt", "line": None,
        "description": "Synthetic advisory", "rule_id": "OSV-TEST-1", "advisory_id": "OSV-TEST-1",
        "aliases": [], "severity": None, "cvss_score": None, "package": "example", "ecosystem": "PyPI",
        "installed_version": "1.0.0", "affected_versions": "< 1.0.1", "fixed_version": "1.0.1", "references": [],
    }
    completed = subprocess.CompletedProcess(["git"], 0, stdout="fixture-sha\n")
    with patch("app.services.scan_service.clone_repo", return_value=str(tmp_path)), patch(
        "app.services.scan_service.subprocess.run", return_value=completed
    ), patch("app.services.scan_service.scan_repository_secrets", return_value=SecretScanResult([secret], "completed", "gitleaks")) as gitleaks, patch(
        "app.services.scan_service.scan_dependencies_with_status",
        return_value=DependencyScanResult([dependency], "completed", None, 1),
    ), patch("app.services.scan_service.repo_signals", return_value={
        "commit_count_90d": 0, "contributor_count": 1, "env_file_tracked": False,
        "gitignore_has_env": True, "has_precommit_secret_hook": True, "historical_secret_count": 0,
        "days_since_last_commit": 0,
    }):
        run_scan(db, scan.id)

    persisted = db.get(Scan, scan.id)
    assert gitleaks.call_count == 1
    assert persisted.status == ScanStatus.done
    assert persisted.scanner_status["secrets"]["source"] == "gitleaks"
    assert persisted.scanner_status["dependencies"]["status"] == "completed"
    dependency_finding = db.scalars(select(DbFinding).where(DbFinding.type == "dependency")).one()
    assert dependency_finding.severity is None
    assert dependency_finding.advisory_id == "OSV-TEST-1"
    db.close()
