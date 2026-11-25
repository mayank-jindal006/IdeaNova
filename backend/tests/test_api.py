from dataclasses import replace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api import create_app
from app.ai.models import Finding
import app.core.scan_paths as scan_paths
from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.scanners.deps import DependencyScanResult
from app.services.gitleaks import SecretScanResult


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    app = create_app()

    def test_db():
        db = Session(engine)
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = test_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def _authenticate(client):
    response = client.post("/api/auth/register", json={"email": "owner@example.test", "password": "test-password-123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _create_repo(client, headers):
    response = client.post(
        "/api/repos",
        headers=headers,
        json={"full_name": "owner/repo", "default_branch": "main"},
    )
    assert response.status_code == 200
    return response.json()["id"]


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_openapi_documents_public_routes(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "/api/repositories/scan" in response.json()["paths"]
    assert "/api/findings/explain" in response.json()["paths"]


def test_scan_rejects_invalid_request_and_returns_request_id(client):
    headers = {**_authenticate(client), "X-Request-ID": "test-request"}
    response = client.post("/api/repositories/scan", json={"repo_id": 0}, headers=headers)

    assert response.status_code == 422
    assert response.headers["X-Request-ID"] == "test-request"
    assert response.json()["error"]["message"] == "Request validation failed"
    assert response.json()["error"]["request_id"] == "test-request"


def test_scan_returns_404_for_missing_repository(client):
    response = client.post("/api/repositories/scan", json={"repo_id": 999999}, headers=_authenticate(client))

    assert response.status_code == 404
    assert response.json()["error"]["message"] == "Repository not found"


def test_repository_registration_rejects_client_filesystem_paths(client):
    headers = _authenticate(client)
    response = client.post(
        "/api/repos",
        headers=headers,
        json={"full_name": "owner/repo", "default_branch": "main", "local_path": "C:/outside"},
    )
    assert response.status_code == 422


def test_scan_fails_safely_when_scan_root_is_not_configured(client, monkeypatch):
    headers = _authenticate(client)
    repo_id = _create_repo(client, headers)
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=None))

    response = client.post("/api/repositories/scan", json={"repo_id": repo_id}, headers=headers)

    assert response.status_code == 503
    assert response.json()["error"]["message"] == "Repository scanning is unavailable"


def test_scan_repository_endpoint(client, tmp_path, monkeypatch):
    repo_dir = tmp_path / "demo-repo"
    repo_dir.mkdir()
    (repo_dir / ".env").write_text("API_KEY=ghp_1234567890\n", encoding="utf-8")
    (repo_dir / "app.py").write_text("token = 'ghp_1234567890'\n", encoding="utf-8")

    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    headers = _authenticate(client)
    repo_id = _create_repo(client, headers)
    with patch("app.routers.repositories.clone_repo", return_value=str(repo_dir)), patch("app.services.gitleaks.shutil.which", return_value=None):
        response = client.post("/api/repositories/scan", json={"repo_id": repo_id}, headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] >= 1
    assert any(finding["file"] == "app.py" or finding["file"] == ".env" for finding in payload["findings"])


def test_scan_endpoint_labels_scanners_and_redacts_gitleaks_secret(client, tmp_path):
    repo_dir = tmp_path / "demo-repo"
    repo_dir.mkdir()
    headers = _authenticate(client)
    repo_id = _create_repo(client, headers)
    secret = Finding(file="app.py", line=2, secret="not-for-response", match="not-for-response", rule_id="test-secret")
    dependencies = DependencyScanResult([
        {"type": "dependency", "scanner": "osv", "file": "requirements.txt", "description": "Test CVE", "rule_id": "OSV-TEST", "severity": "high", "package": "example", "ecosystem": "PyPI", "installed_version": "1.0.0", "fixed_version": "1.0.1", "references": []}
    ], "completed", None, 1)
    with patch("app.routers.repositories.clone_repo", return_value=str(repo_dir)), patch("app.routers.repositories.scan_repository_secrets", return_value=SecretScanResult([secret], "completed", "gitleaks")), patch("app.routers.repositories.scan_dependencies_with_status", return_value=dependencies):
        response = client.post("/api/repositories/scan", json={"repo_id": repo_id}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["scanners"]["secrets"] == {"status": "completed", "source": "gitleaks", "reason": None, "count": 1}
    assert body["scanners"]["dependencies"]["status"] == "completed"
    assert {finding["type"] for finding in body["findings"]} == {"secret", "dependency"}
    assert "not-for-response" not in str(body)


def test_explain_finding_endpoint_redacts_inline_secrets(client):
    headers = _authenticate(client)
    payload = {
        "finding": {
            "file": "src/config.js",
            "StartLine": 8,
            "EndLine": 8,
            "StartColumn": 14,
            "EndColumn": 35,
            "Secret": "AKIA1234567890EXAMPLE",
            "RuleID": "aws-access-token",
            "Severity": "critical",
        },
        "source_context": "const key = 'AKIA1234567890EXAMPLE';\nexport default key;",
    }

    with patch("app.routers.findings.generate_security_recommendation", return_value={
        "summary": "Rule-based guidance",
        "risk_assessment": "Risk",
        "remediation": "Remediate",
        "developer_summary": "Prevent",
        "requires_rotation": True,
        "confidence": 0.9,
        "guidance_source": "rule_based_fallback",
        "guidance_failure_reason": "network_or_connection",
    }) as generate:
        response = client.post("/api/findings/explain", json=payload, headers=headers)

    assert response.status_code == 200
    assert generate.call_count == 1
    body = response.json()
    assert "explanation" in body
    assert body["explanation"]["guidance_failure_reason"] == "network_or_connection"
    assert "AKIA1234567890EXAMPLE" not in str(body)


def test_explain_finding_preserves_dependency_metadata(client):
    headers = _authenticate(client)
    finding = {
        "type": "dependency",
        "scanner": "osv",
        "file": "package-lock.json",
        "rule_id": "GHSA-test-1234",
        "advisory_id": "GHSA-test-1234",
        "package": "source-map-js",
        "ecosystem": "npm",
        "installed_version": "1.2.1",
        "affected_versions": ">= 1.0.0, < 1.2.2",
        "fixed_version": "1.2.2",
        "aliases": ["CVE-2026-12345"],
        "references": ["https://example.invalid/advisory"],
    }
    explanation = {
        "summary": "Dependency advisory applies.",
        "risk_assessment": "The installed dependency is affected.",
        "remediation": "Upgrade to the verified fixed release 1.2.2.",
        "developer_summary": "Rescan after upgrading.",
        "requires_rotation": False,
        "confidence": 0.94,
        "guidance_source": "rule_based_fallback",
    }
    with patch("app.routers.findings.generate_security_recommendation", return_value=explanation) as generate:
        response = client.post("/api/findings/explain", json={"finding": finding}, headers=headers)

    assert response.status_code == 200
    returned_finding = response.json()["finding"]
    generated_finding = generate.call_args.args[0]
    assert generated_finding.type == "dependency"
    assert generated_finding.package == "source-map-js"
    assert generated_finding.installed_version == "1.2.1"
    assert generated_finding.affected_versions == ">= 1.0.0, < 1.2.2"
    assert generated_finding.fixed_version == "1.2.2"
    assert returned_finding["advisory_id"] == "GHSA-test-1234"
    assert returned_finding["aliases"] == ["CVE-2026-12345"]
    assert returned_finding["references"] == ["https://example.invalid/advisory"]


def test_explain_rejects_unknown_finding_fields(client):
    response = client.post(
        "/api/findings/explain",
        json={"finding": {"file": "x.py", "unexpected": "value"}},
        headers=_authenticate(client),
    )

    assert response.status_code == 422
    assert response.json()["error"]["message"] == "Finding payload is invalid"
