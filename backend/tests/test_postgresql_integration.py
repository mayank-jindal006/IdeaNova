from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import string
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import QueuePool

from app.ai.llm import LLMError
from app.db.models import Finding, Repo, RevokedToken, Scan, User
from app.db.session import get_db
from app.main import create_app
from app.settings import settings as runtime_settings


@pytest.fixture
def postgres_engine():
    database_url = os.getenv("REPOGUARD_PG_TEST_URL")
    if not database_url:
        pytest.skip("Set REPOGUARD_PG_TEST_URL to an isolated local PostgreSQL test database")
    url = make_url(database_url)
    if (
        url.drivername != "postgresql+psycopg"
        or url.host not in {"127.0.0.1", "localhost"}
        or not url.database
        or not url.database.startswith("repoguard_phase7")
    ):
        pytest.fail("PostgreSQL integration tests require a loopback disposable repoguard_phase7 database")

    from sqlalchemy import create_engine

    engine = create_engine(database_url, pool_pre_ping=True, pool_size=5, max_overflow=10)
    try:
        yield engine
    finally:
        engine.dispose()


def test_postgresql_schema_pooling_and_transaction_rollback(postgres_engine):
    assert isinstance(postgres_engine.pool, QueuePool)
    assert postgres_engine.pool.size() == 5
    assert postgres_engine.pool._pre_ping is True
    with postgres_engine.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar_one() == 1
    assert postgres_engine.pool.checkedout() == 0

    inspector = inspect(postgres_engine)
    tables = set(inspector.get_table_names())
    assert {
        "users",
        "repos",
        "scans",
        "findings",
        "fixes",
        "feedback",
        "repo_scores",
        "revoked_tokens",
        "alembic_version",
    }.issubset(tables)
    repo_columns = {column["name"] for column in inspector.get_columns("repos")}
    scan_columns = {column["name"]: column["type"] for column in inspector.get_columns("scans")}
    assert "owner_id" in repo_columns
    assert "local_path" not in repo_columns
    assert {"ref", "commit_sha", "scanner_status"}.issubset(scan_columns)
    assert isinstance(scan_columns["scanner_status"], JSONB)

    finding_columns = {column["name"]: column["type"] for column in inspector.get_columns("findings")}
    assert isinstance(finding_columns["aliases"], ARRAY)
    assert isinstance(finding_columns["references"], ARRAY)
    assert isinstance(finding_columns["owasp_ids"], ARRAY)
    assert isinstance(finding_columns["asvs_ids"], ARRAY)
    assert not any(
        isinstance(column["type"], UUID)
        for table in tables
        for column in inspector.get_columns(table)
    )
    repo_indexes = inspector.get_indexes("repos")
    assert any(index["name"] == "ix_repos_owner_id" for index in repo_indexes)
    assert any(index["name"] == "uq_repos_owner_full_name_ci" and index["unique"] for index in repo_indexes)
    assert any(key["name"] == "repos_owner_id_fkey" for key in inspector.get_foreign_keys("repos"))
    assert any(key["name"] == "scans_repo_id_fkey" for key in inspector.get_foreign_keys("scans"))
    assert any(key["name"] == "findings_scan_id_fkey" for key in inspector.get_foreign_keys("findings"))
    assert any(key["name"] == "findings_repo_id_fkey" for key in inspector.get_foreign_keys("findings"))
    assert any(key["name"] == "revoked_tokens_user_id_fkey" for key in inspector.get_foreign_keys("revoked_tokens"))
    with Session(postgres_engine) as db:
        version = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert version == "0007_phase7_deployment"
        user = User(email=f"rollback-{uuid.uuid4().hex}@example.test", password_hash="synthetic")
        db.add(user)
        db.flush()
        user_id = user.id
        db.rollback()
    with Session(postgres_engine) as db:
        assert db.get(User, user_id) is None


@pytest.mark.skipif(
    os.getenv("REPOGUARD_LIVE_SCANNER_TESTS") != "1",
    reason="Set REPOGUARD_LIVE_SCANNER_TESTS=1 to run live scanner end-to-end coverage",
)
def test_postgresql_authenticated_end_to_end_and_webhook_fanout(
    postgres_engine,
    tmp_path,
    monkeypatch,
    caplog,
):
    gitleaks_bin = os.getenv("GITLEAKS_BIN")
    if not gitleaks_bin or not Path(gitleaks_bin).is_file():
        pytest.fail("Live end-to-end scan requires GITLEAKS_BIN to point to pinned Gitleaks")

    from app.db.models import ScanStatus, ScanTrigger
    from app.core.process_env import subprocess_environment
    from app.services.scan_service import run_scan

    scan_root = tmp_path.parent
    source = tmp_path / "synthetic-github-repo"
    repository_name = f"phase7-fixtures/synthetic-{uuid.uuid4().hex[:8]}"
    source.mkdir()
    git_environment = subprocess_environment()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source, check=True, env=git_environment)
    subprocess.run(["git", "config", "user.name", "RepoGuard Test"], cwd=source, check=True, env=git_environment)
    subprocess.run(
        ["git", "config", "user.email", "repoguard-test@example.invalid"],
        cwd=source,
        check=True,
        env=git_environment,
    )
    synthetic_secret = "ghp_" + "".join(
        secrets.choice(string.ascii_letters + string.digits + "_") for _ in range(40)
    )
    (source / "synthetic.txt").write_text(f"token={synthetic_secret}\n", encoding="utf-8")
    (source / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=source, check=True, env=git_environment)
    subprocess.run(["git", "commit", "-q", "-m", "synthetic RepoGuard test fixture"], cwd=source, check=True, env=git_environment)
    pushed_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
        env=git_environment,
    ).stdout.strip()

    def get_db_override():
        with Session(postgres_engine) as db:
            yield db

    def run_disposable_scan(scan_id: int) -> None:
        with Session(postgres_engine) as db:
            run_scan(db, scan_id)

    def clone_synthetic_repository(full_name: str, commit_sha: str | None = None, ref: str | None = None) -> str:
        assert full_name == repository_name
        if commit_sha:
            assert commit_sha == pushed_sha
            assert ref == "refs/heads/feature/phase7"
        checkout = tmp_path / f"checkout-{uuid.uuid4().hex}"
        shutil.copytree(source, checkout)
        return str(checkout)

    monkeypatch.setattr("app.main.engine", postgres_engine)
    monkeypatch.setattr("app.services.scan_service.clone_repo", clone_synthetic_repository)
    monkeypatch.setattr("app.api.repos._background_scan", run_disposable_scan)
    monkeypatch.setattr("app.api.webhooks._background_scan", run_disposable_scan)
    monkeypatch.setattr(
        "app.services.ai_service.complete_json",
        lambda **_: (_ for _ in ()).throw(LLMError("provider unavailable", category="unconfigured")),
    )
    webhook_secret = f"synthetic-webhook-{uuid.uuid4().hex}"
    monkeypatch.setattr(
        "app.github_client.client.settings",
        replace(runtime_settings, github_webhook_secret=webhook_secret),
    )
    app = create_app()
    app.dependency_overrides[get_db] = get_db_override

    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").json() == {"status": "ready"}

        first_email = f"phase7-a-{uuid.uuid4().hex}@example.test"
        registered = client.post(
            "/api/auth/register",
            json={
                "email": first_email,
                "password": "test-only-password-a-123",
            },
        )
        assert registered.status_code == 200
        logged_in = client.post(
            "/api/auth/login",
            json={"email": first_email, "password": "test-only-password-a-123"},
        )
        assert logged_in.status_code == 200
        first_token = logged_in.json()["access_token"]
        first_headers = {"Authorization": f"Bearer {first_token}"}
        assert client.get("/api/auth/me", headers=first_headers).json()["email"] == first_email

        created_repo = client.post(
            "/api/repos",
            headers=first_headers,
            json={"full_name": repository_name, "default_branch": "main"},
        )
        assert created_repo.status_code == 200
        first_repo_id = created_repo.json()["id"]
        assert client.post(
            "/api/repos",
            headers=first_headers,
            json={"full_name": repository_name.upper(), "default_branch": "main"},
        ).status_code == 409

        queued = client.post(f"/api/repos/{first_repo_id}/scan", headers=first_headers)
        assert queued.status_code == 200
        scan_id = queued.json()["scan_id"]
        scan = client.get(f"/api/scans/{scan_id}", headers=first_headers)
        assert scan.status_code == 200
        assert scan.json()["status"] == "done"
        assert scan.json()["commit_sha"] == pushed_sha
        assert scan.json()["scanner_status"]["secrets"]["source"] == "gitleaks"
        assert scan.json()["scanner_status"]["secrets"]["status"] == "completed"
        assert scan.json()["scanner_status"]["dependencies"]["source"] == "osv"
        assert scan.json()["scanner_status"]["dependencies"]["status"] in {"completed", "empty"}

        scan_findings_response = client.get(
            f"/api/scans/{scan_id}/findings",
            headers=first_headers,
        )
        assert scan_findings_response.status_code == 200
        scan_findings = scan_findings_response.json()
        secret_findings = [item for item in scan_findings if item["type"] == "secret"]
        dependency_findings = [item for item in scan_findings if item["type"] == "dependency"]
        assert secret_findings
        assert dependency_findings
        secret_finding = secret_findings[0]
        assert secret_finding["file_path"] == "synthetic.txt"
        assert secret_finding["line"] == 1
        assert secret_finding["severity"] == "high"
        assert synthetic_secret not in scan_findings_response.text
        assert all(item["severity"] is None or item["severity"] in {"critical", "high", "medium", "low"} for item in dependency_findings)
        assert any(item["severity"] is None for item in dependency_findings)

        finding_detail = client.get(
            f"/api/findings/{secret_finding['id']}",
            headers=first_headers,
        )
        assert finding_detail.status_code == 200
        assert synthetic_secret not in finding_detail.text
        explanation = client.post(
            "/api/findings/explain",
            headers=first_headers,
            json={
                "finding": {
                    "type": "secret",
                    "scanner": "gitleaks",
                    "file": secret_finding["file_path"],
                    "line": secret_finding["line"],
                    "description": secret_finding["title"],
                    "rule_id": secret_finding["rule_id"],
                    "severity": secret_finding["severity"],
                },
                "source_context": "",
            },
        )
        assert explanation.status_code == 200
        assert explanation.json()["explanation"]["guidance_source"] == "rule_based_fallback"
        assert synthetic_secret not in explanation.text
        dashboard = client.get("/api/dashboard/summary", headers=first_headers)
        assert dashboard.status_code == 200
        assert dashboard.json()["totals"]["repos"] == 1
        assert dashboard.json()["totals"]["open_findings"] >= 1
        assert not list(tmp_path.glob("checkout-*"))

        second_email = f"phase7-b-{uuid.uuid4().hex}@example.test"
        second_registration = client.post(
            "/api/auth/register",
            json={
                "email": second_email,
                "password": "test-only-password-b-123",
            },
        )
        assert second_registration.status_code == 200
        second_login = client.post(
            "/api/auth/login",
            json={"email": second_email, "password": "test-only-password-b-123"},
        )
        assert second_login.status_code == 200
        second_token = second_login.json()["access_token"]
        second_headers = {"Authorization": f"Bearer {second_token}"}
        same_repo = client.post(
            "/api/repos",
            headers=second_headers,
            json={"full_name": repository_name, "default_branch": "main"},
        )
        assert same_repo.status_code == 200
        second_repo_id = same_repo.json()["id"]
        assert second_repo_id != first_repo_id
        assert client.get(f"/api/scans/{scan_id}", headers=second_headers).status_code == 404
        assert client.get(
            f"/api/findings/{secret_finding['id']}",
            headers=second_headers,
        ).status_code == 404

        payload = {
            "ref": "refs/heads/feature/phase7",
            "after": pushed_sha,
            "deleted": False,
            "repository": {"full_name": repository_name},
        }
        body = json.dumps(payload).encode()
        signature = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        webhook_headers = {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": f"sha256={signature}",
        }
        webhook_response = client.post(
            "/api/webhooks/github",
            content=body,
            headers=webhook_headers,
        )
        redelivery = client.post(
            "/api/webhooks/github",
            content=body,
            headers=webhook_headers,
        )
        assert webhook_response.status_code == 200
        assert webhook_response.json() == {"queued": 2}
        assert redelivery.json() == {"queued": 0}
        with Session(postgres_engine) as db:
            webhook_scans = db.scalars(
                select(Scan).where(
                    Scan.trigger == ScanTrigger.push,
                    Scan.commit_sha == pushed_sha,
                )
            ).all()
            assert {item.repo_id for item in webhook_scans} == {first_repo_id, second_repo_id}
            assert all(item.ref == "refs/heads/feature/phase7" for item in webhook_scans)
            assert all(item.status == ScanStatus.done for item in webhook_scans)
            assert db.scalar(select(Finding.id).where(Finding.repo_id == first_repo_id)) is not None
            assert db.scalar(select(Finding.id).where(Finding.repo_id == second_repo_id)) is not None
            assert db.scalar(select(RevokedToken.token_id)) is None

        logout = client.post("/api/auth/logout", headers=first_headers)
        assert logout.status_code == 204
        assert client.get("/api/auth/me", headers=first_headers).status_code == 401
        assert client.get("/api/auth/me", headers=second_headers).status_code == 200

    app.dependency_overrides.clear()
    assert not list(tmp_path.glob("checkout-*"))
    assert not any(synthetic_secret in record.getMessage() for record in caplog.records)
    assert postgres_engine.pool.checkedout() == 0
