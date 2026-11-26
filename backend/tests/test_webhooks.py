import hashlib
import hmac
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Finding, FindingStatus, FindingType, Repo, Scan, ScanStatus, ScanTrigger, User
from app.db.session import get_db
from app.main import create_app
from app.settings import settings as runtime_settings


WEBHOOK_SECRET = "test-webhook-secret"


@pytest.fixture
def webhook_client(monkeypatch):
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
    monkeypatch.setattr(
        "app.github_client.client.settings",
        replace(runtime_settings, github_webhook_secret=WEBHOOK_SECRET),
    )
    with TestClient(app) as test_client:
        yield test_client, engine
    app.dependency_overrides.clear()
    engine.dispose()


def _push_payload(ref: str, commit_sha: str, *, deleted: bool = False) -> dict:
    return {
        "ref": ref,
        "after": commit_sha,
        "deleted": deleted,
        "repository": {"full_name": "Owner/Repo"},
    }


def _send_push(client, payload: dict):
    body = json.dumps(payload).encode()
    signature = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/api/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": f"sha256={signature}",
        },
    )


def _add_repo(engine, owner_email: str, full_name: str = "owner/repo") -> tuple[int, int]:
    with Session(engine) as db:
        user = User(email=owner_email, password_hash="fixture")
        db.add(user)
        db.flush()
        repo = Repo(owner_id=user.id, full_name=full_name, default_branch="main")
        db.add(repo)
        db.commit()
        return user.id, repo.id


@pytest.mark.parametrize(
    ("ref", "commit_sha"),
    [
        ("refs/heads/main", "1" * 40),
        ("refs/heads/feature/security", "2" * 40),
    ],
)
def test_webhook_queues_exact_commit_and_ref_and_deduplicates(webhook_client, ref, commit_sha):
    client, engine = webhook_client
    _, repo_id = _add_repo(engine, "owner@example.test")

    with patch("app.api.webhooks._background_scan") as background_scan:
        response = _send_push(client, _push_payload(ref, commit_sha))
        repeated = _send_push(client, _push_payload(ref, commit_sha))

    assert response.status_code == 200
    assert response.json() == {"queued": 1}
    assert repeated.status_code == 200
    assert repeated.json() == {"queued": 0}
    with Session(engine) as db:
        scans = db.scalars(select(Scan).where(Scan.repo_id == repo_id)).all()
        assert len(scans) == 1
        assert scans[0].trigger == ScanTrigger.push
        assert scans[0].commit_sha == commit_sha
        assert scans[0].ref == ref
    assert background_scan.call_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"repository": {"full_name": "owner/repo"}, "ref": "refs/tags/v1", "after": "a" * 40},
        {"repository": {"full_name": "../outside"}, "ref": "refs/heads/main", "after": "a" * 40},
        {"repository": {"full_name": "owner/repo"}, "ref": "refs/heads/main", "after": "invalid"},
        {"repository": {"full_name": "owner/repo"}, "ref": "refs/heads/main", "after": "a" * 40},
    ],
)
def test_webhook_rejects_invalid_push_payloads(webhook_client, payload):
    client, _ = webhook_client

    response = _send_push(client, payload)

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "Webhook payload is invalid"


def test_webhook_ignores_valid_deleted_branch(webhook_client):
    client, engine = webhook_client
    _add_repo(engine, "owner@example.test")
    payload = _push_payload("refs/heads/feature/removed", "0" * 40, deleted=True)

    response = _send_push(client, payload)

    assert response.status_code == 200
    assert response.json() == {"queued": 0, "deleted": True}
    with Session(engine) as db:
        assert db.scalar(select(Scan.id)) is None


def test_webhook_queues_all_tenants_and_keeps_scan_and_finding_isolated(webhook_client):
    client, engine = webhook_client
    _, first_repo_id = _add_repo(engine, "first@example.test")
    _, second_repo_id = _add_repo(engine, "second@example.test", "OWNER/REPO")
    commit_sha = "3" * 40

    with patch("app.api.webhooks._background_scan") as background_scan:
        response = _send_push(client, _push_payload("refs/heads/feature/api", commit_sha))

    assert response.status_code == 200
    assert response.json() == {"queued": 2}
    assert background_scan.call_count == 2
    with Session(engine) as db:
        scans = db.scalars(select(Scan).order_by(Scan.repo_id)).all()
        assert [scan.repo_id for scan in scans] == [first_repo_id, second_repo_id]
        assert all(scan.commit_sha == commit_sha for scan in scans)
        finding_ids = []
        for scan in scans:
            finding = Finding(
                scan_id=scan.id,
                repo_id=scan.repo_id,
                fingerprint=f"fixture-{scan.repo_id}",
                type=FindingType.secret,
                rule_id="fixture",
                title="fixture finding",
                severity=None,
                scanner="gitleaks",
                aliases=[],
                references=[],
                in_history_only=False,
                confidence=0.9,
                status=FindingStatus.open,
                owasp_ids=[],
                asvs_ids=[],
            )
            db.add(finding)
            db.flush()
            finding_ids.append(finding.id)
        users = db.scalars(select(User).order_by(User.id)).all()
        from app.auth import issue_token

        first_token, second_token = (issue_token(user) for user in users)
        first_scan_id, second_scan_id = (scan.id for scan in scans)
        db.commit()

    first_headers = {"Authorization": f"Bearer {first_token}"}
    second_headers = {"Authorization": f"Bearer {second_token}"}
    assert client.get(f"/api/scans/{first_scan_id}", headers=first_headers).status_code == 200
    assert client.get(f"/api/findings/{finding_ids[0]}", headers=first_headers).status_code == 200
    assert client.get(f"/api/scans/{second_scan_id}", headers=first_headers).status_code == 404
    assert client.get(f"/api/findings/{finding_ids[1]}", headers=first_headers).status_code == 404
    assert client.get(f"/api/scans/{second_scan_id}", headers=second_headers).status_code == 200
