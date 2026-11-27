import hashlib
import subprocess
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient
from github import GithubException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api import create_app
from app.ai.fix import generate_fix
from app.ai.llm import LLMError, ProviderResponse
from app.ai.models import Finding as ScannerFinding
from app.db.base import Base
from app.db.models import (
    AuditLog,
    AiRequestLog,
    Finding,
    FindingStatus,
    FindingType,
    Fix,
    FixReview,
    FixStatus,
    FixTier,
    GitHubSubmissionAttempt,
    Repo,
    RepoScore,
    Scan,
    ScanStatus,
    ScanTrigger,
    User,
)
from app.db.session import get_db
from app.scanners.deps import scan_dependencies_with_status
from app.services.audit import list_owned_audit_events
from app.services.gitleaks import SecretScanResult
from app.services.scan_service import run_scan
from app.scanners.deps import DependencyScanResult
from app.api.findings import _finding_context, _read_finding_file
from app.services.proposal_integrity import proposal_digest


def test_local_approval_binds_proposal_and_validation_rejects_changes(api_database):
    client, engine = api_database
    owner = _register(client, "digest-owner@example.test")
    other = _register(client, "digest-other@example.test")
    _, fix_id = _seed_fix(engine, "digest-owner@example.test")
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        finding = db.get(Finding, fix.finding_id)
        db.get(Repo, finding.repo_id).local_path = "synthetic-local-path"
        db.commit()
    assert client.post(f"/api/fixes/{fix_id}/review", headers=other, json={"decision": "approved"}).status_code == 404
    assert client.post(f"/api/fixes/{fix_id}/validate", headers=owner).status_code == 409
    assert client.post(f"/api/fixes/{fix_id}/review", headers=owner, json={"decision": "approved"}).status_code == 200
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        review = db.scalar(select(FixReview).where(FixReview.fix_id == fix_id))
        assert review.proposal_digest == proposal_digest(fix)
        fix.patch += "changed"
        db.commit()
    with patch("app.api.fixes.validate_fix_candidate") as validate:
        assert client.post(f"/api/fixes/{fix_id}/validate", headers=owner).status_code == 409
        validate.assert_not_called()


def test_local_validation_records_digest_and_disables_pr(api_database):
    client, engine = api_database
    owner = _register(client, "validated-owner@example.test")
    _, fix_id = _seed_fix(engine, "validated-owner@example.test")
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        db.get(Repo, db.get(Finding, fix.finding_id).repo_id).local_path = "synthetic-local-path"
        db.commit()
    assert client.post(f"/api/fixes/{fix_id}/review", headers=owner, json={"decision": "approved"}).status_code == 200
    result = {"secret_removed": False, "syntax_ok": True, "patch_syntax": "passed", "target_exists": True, "tests": "not_run", "security_rescan": "passed", "notes": []}
    with patch("app.api.fixes.validate_fix_candidate", return_value=result):
        assert client.post(f"/api/fixes/{fix_id}/validate", headers=owner).status_code == 200
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        assert fix.validation["proposal_digest"] == proposal_digest(fix)
    assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=owner).status_code == 409


def test_local_validation_rejects_proposal_changed_during_scan(api_database):
    client, engine = api_database
    owner = _register(client, "during-validation@example.test")
    _, fix_id = _seed_fix(engine, "during-validation@example.test")
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        db.get(Repo, db.get(Finding, fix.finding_id).repo_id).local_path = "synthetic-local-path"
        db.commit()
    assert client.post(f"/api/fixes/{fix_id}/review", headers=owner, json={"decision": "approved"}).status_code == 200

    def change_during_validation(*_):
        with Session(engine) as db:
            fix = db.get(Fix, fix_id)
            fix.patch += "changed during validation"
            db.commit()
        return {"secret_removed": False, "syntax_ok": True, "patch_syntax": "passed", "target_exists": True, "tests": "not_run", "security_rescan": "passed", "notes": []}

    with patch("app.api.fixes.validate_fix_candidate", side_effect=change_during_validation):
        assert client.post(f"/api/fixes/{fix_id}/validate", headers=owner).status_code == 409
    with Session(engine) as db:
        assert db.get(Fix, fix_id).status == FixStatus.approved


def test_local_application_is_not_exposed_even_after_validation(api_database, tmp_path):
    client, engine = api_database
    owner = _register(client, "no-application@example.test")
    finding_id, fix_id = _seed_fix(engine, "no-application@example.test")
    target = tmp_path / "requirements.txt"
    target.write_bytes(b"synthetic-original\n")
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        db.get(Repo, db.get(Finding, finding_id).repo_id).local_path = str(tmp_path)
        fix.status = FixStatus.validation_passed
        db.commit()
    assert client.post(f"/api/fixes/{fix_id}/apply", headers=owner).status_code == 404
    assert target.read_bytes() == b"synthetic-original\n"


@pytest.fixture
def api_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    app = create_app()

    def test_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    with TestClient(app) as client:
        yield client, engine
    app.dependency_overrides.clear()
    engine.dispose()


def _register(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": "synthetic-test-password-123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _seed_fix(engine, email: str) -> tuple[int, int]:
    with Session(engine) as db:
        user = db.scalar(select(User).where(User.email == email))
        repo = Repo(owner_id=user.id, full_name=f"{email.split('@')[0]}/repo", default_branch="main")
        db.add(repo)
        db.flush()
        scan = Scan(repo_id=repo.id, trigger=ScanTrigger.manual, status=ScanStatus.done)
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            repo_id=repo.id,
            fingerprint=f"fingerprint-{email}",
            type=FindingType.dependency,
            rule_id="OSV-TEST-1",
            title="Synthetic dependency finding",
            description="Synthetic dependency finding",
            severity=None,
            scanner="osv",
            package="example",
            ecosystem="PyPI",
            installed_version="1.0.0",
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
        fix = Fix(
            finding_id=finding.id,
            explanation={
                "what": "A synthetic issue was found.",
                "why_dangerous": "The example version is affected.",
                "how_fixed": "Update to the verified fixed version.",
                "rotation_required": False,
                "rotation_note": "No credential rotation is indicated.",
            },
            edits=[{"file_path": "app.py", "new_content": "value = 2\n"}],
            patch="--- a/app.py\n+++ b/app.py\n",
            target_file="app.py",
            base_hash=hashlib.sha256(b"value = 1\n").hexdigest(),
            risk_level="medium",
            tier=FixTier.pr_review,
            validation={
                "secret_removed": False,
                "syntax_ok": True,
                "patch_syntax": "passed",
                "target_exists": True,
                "tests": "not_run",
                "security_rescan": "not_run",
                "notes": [],
            },
            status=FixStatus.pending_review,
        )
        db.add(fix)
        db.commit()
        return finding.id, fix.id


@pytest.mark.parametrize(
    ("model_payload", "usage", "provider_error", "expected_source", "expected_status", "failure_category"),
    [
        ({"summary": "Synthetic issue", "risk_assessment": "Assess exposure", "remediation": "Review dependencies", "developer_summary": "Rescan", "requires_rotation": False, "confidence": 0.8}, None, None, "gemini", "completed", None),
        ({"summary": "Incomplete"}, ProviderResponse("{}", 10, 5), None, "rule_based_fallback", "fallback", "malformed_response"),
        (None, None, LLMError("Synthetic timeout", category="timeout"), "rule_based_fallback", "fallback", "timeout"),
    ],
)
def test_persisted_explanation_log_tracks_final_guidance_source(
    api_database, model_payload, usage, provider_error, expected_source, expected_status, failure_category
):
    client, engine = api_database
    headers = _register(client, "explanation-owner@example.test")
    finding_id, _ = _seed_fix(engine, "explanation-owner@example.test")
    with patch("app.services.ai_service.complete_json_with_metadata", side_effect=provider_error, return_value=(model_payload, usage)) as provider:
        response = client.post(f"/api/findings/{finding_id}/explain", headers=headers)

    assert response.status_code == 200
    provider.assert_called_once()
    explanation = response.json()["explanation"]
    assert explanation["guidance_source"] == expected_source
    assert explanation.get("guidance_failure_reason") == failure_category
    with Session(engine) as db:
        log = db.scalars(select(AiRequestLog).where(AiRequestLog.finding_id == finding_id, AiRequestLog.purpose == "explanation")).one()
        assert log.status == expected_status
        assert log.failure_category == failure_category
        assert log.result == explanation
        assert log.input_tokens == (usage.input_tokens if usage else None)
        assert log.output_tokens == (usage.output_tokens if usage else None)


def test_finding_source_reader_keeps_full_file_for_patch_and_bounds_context(tmp_path):
    source = "\n".join(f"value_{line} = {line}" for line in range(1, 81)) + "\n"
    (tmp_path / "module.py").write_text(source, encoding="utf-8")
    expected_hash = hashlib.sha256((tmp_path / "module.py").read_bytes()).hexdigest()
    repo = Repo(full_name="owner/repo", default_branch="main")
    with patch("app.api.findings.require_scan_root"), patch(
        "app.api.findings.clone_repo", return_value=str(tmp_path)
    ), patch("app.api.findings.validate_scan_path", return_value=tmp_path), patch(
        "app.api.findings.scan_repository_secrets",
        return_value=SecretScanResult([], "empty", "gitleaks"),
    ):
        complete_source, source_hash = _read_finding_file(repo, "module.py")

    context = _finding_context(complete_source, 40)
    assert complete_source.replace("\r\n", "\n") == source
    assert source_hash == expected_hash
    assert "value_40 = 40" in context
    assert "value_1 = 1" not in context
    assert "value_80 = 80" not in context


def test_finding_source_reader_redacts_secret_lines_before_ai_use(tmp_path):
    source = "name = 'example'\npassword = 'synthetic-only-token'\n"
    (tmp_path / "module.py").write_text(source, encoding="utf-8")
    scanner_finding = ScannerFinding(
        file="module.py",
        line=2,
        start_line=2,
        end_line=2,
        start_column=13,
        end_column=34,
        secret="synthetic-only-token",
        match="synthetic-only-token",
        rule_id="generic-api-key",
    )
    repo = Repo(full_name="owner/repo", default_branch="main")
    with patch("app.api.findings.require_scan_root"), patch(
        "app.api.findings.clone_repo", return_value=str(tmp_path)
    ), patch("app.api.findings.validate_scan_path", return_value=tmp_path), patch(
        "app.api.findings.scan_repository_secrets",
        return_value=SecretScanResult([scanner_finding], "completed", "gitleaks"),
    ):
        redacted_source, _ = _read_finding_file(repo, "module.py")

    assert "synthetic-only-token" not in redacted_source
    assert "[REDACTED]" in redacted_source


def test_fix_generator_uses_full_file_and_builds_patch_server_side():
    source = "def configure():\n    value = 'old'\n    return value\n"
    replacement = "def configure():\n    value = 'new'\n    return value\n"
    model_response = {
        "what": "Replace the unsafe value.",
        "why_dangerous": "The original value was unsafe.",
        "how_fixed": "Use the reviewed replacement.",
        "new_content": replacement,
    }
    with patch(
        "app.ai.fix.complete_json_with_metadata",
        return_value=(model_response, ProviderResponse("{}", 10, 5)),
    ) as complete:
        result = generate_fix(
            {"type": "dependency", "severity": "medium", "secret": "synthetic-secret"},
            "app.py",
            source,
        )

    assert result["status"] == "pending_review"
    assert result["edits"] == [{"file_path": "app.py", "new_content": replacement}]
    assert result["patch"].startswith("--- a/app.py\n+++ b/app.py\n")
    assert source in complete.call_args.kwargs["user"]
    assert "synthetic-secret" not in complete.call_args.kwargs["user"]


def test_secret_finding_does_not_send_source_to_ai_or_create_a_patch():
    with patch("app.ai.fix.complete_json_with_metadata") as complete:
        result = generate_fix(
            {"type": "secret", "severity": "critical", "title": "Synthetic secret"},
            "settings.py",
            "API_TOKEN = 'synthetic-only-value'\n",
        )

    complete.assert_not_called()
    assert result["patch"] is None
    assert result["tier"] == "flag_only"


def test_fix_workflow_requires_approval_then_validates_and_opens_real_pr(api_database, tmp_path):
    client, engine = api_database
    headers = _register(client, "fix-owner@example.test")
    _, fix_id = _seed_fix(engine, "fix-owner@example.test")
    validation = {
        "secret_removed": False,
        "syntax_ok": True,
        "patch_syntax": "passed",
        "target_exists": True,
        "tests": "not_run",
        "security_rescan": "passed",
        "notes": ["Synthetic validation passed."],
    }

    response = client.post(f"/api/fixes/{fix_id}/validate", headers=headers)
    assert response.status_code == 409
    response = client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers)
    assert response.status_code == 409

    response = client.post(
        f"/api/fixes/{fix_id}/review",
        headers=headers,
        json={"decision": "approved", "note": "Reviewed synthetic proposal"},
    )
    assert response.status_code == 200
    assert response.json()["fix"]["status"] == "approved"

    with patch("app.api.fixes.validate_fix_candidate", return_value=validation) as validate:
        response = client.post(f"/api/fixes/{fix_id}/validate", headers=headers)
    assert response.status_code == 200
    assert response.json()["fix"]["status"] == "validation_passed"
    validate.assert_called_once()

    (tmp_path / "app.py").write_bytes(b"value = 1\n")
    with patch("app.api.fixes.require_connected_github"), patch("app.api.fixes.require_scan_root"), patch(
        "app.api.fixes.clone_repo", return_value=str(tmp_path)
    ), patch("app.api.fixes.validate_scan_path", return_value=tmp_path), patch(
        "app.api.fixes.subprocess.run",
        return_value=subprocess.CompletedProcess(["git"], 0, stdout=f"{'a' * 40}\n"),
    ), patch("app.api.fixes.create_branch") as create_branch, patch(
        "app.api.fixes.commit_file_changes"
    ) as commit_changes, patch(
        "app.api.fixes.open_pull_request",
        return_value=("https://github.com/example/repo/pull/7", 7),
    ) as open_pr:
        response = client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers)

    assert create_branch.call_count == 1, response.status_code
    assert commit_changes.call_count == 1, response.status_code
    assert open_pr.call_count == 1, response.status_code
    assert response.status_code == 200
    assert response.json() == {"pr_url": "https://github.com/example/repo/pull/7", "pr_number": 7}
    create_branch.assert_called_once()
    commit_changes.assert_called_once()
    detail = client.get(f"/api/fixes/{fix_id}", headers=headers)
    assert detail.json()["fix"]["status"] == "pr_opened"
    assert detail.json()["fix"]["pr_url"] == "https://github.com/example/repo/pull/7"
    assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers).status_code == 409
    create_branch.assert_called_once()
    assert create_branch.call_args.kwargs["base_sha"] == "a" * 40
    assert create_branch.call_args.args[2] == "main"


def test_fix_and_audit_records_are_tenant_scoped(api_database):
    client, engine = api_database
    owner_headers = _register(client, "owner@example.test")
    other_headers = _register(client, "other@example.test")
    _, fix_id = _seed_fix(engine, "owner@example.test")
    _seed_fix(engine, "other@example.test")

    with Session(engine) as db:
        owner = db.scalar(select(User).where(User.email == "owner@example.test"))
        other = db.scalar(select(User).where(User.email == "other@example.test"))
        owner_repo = db.scalar(select(Repo).where(Repo.owner_id == owner.id))
        other_repo = db.scalar(select(Repo).where(Repo.owner_id == other.id))
        db.add(AuditLog(user_id=owner.id, actor_email=owner.email, repo_id=owner_repo.id, action="owner.event", details={}))
        db.add(AuditLog(user_id=other.id, actor_email=other.email, repo_id=other_repo.id, action="foreign.event", details={}))
        db.add(AuditLog(action="unrelated.event", details={}))
        db.commit()

    own_fix = client.get(f"/api/fixes/{fix_id}", headers=owner_headers)
    foreign_fix = client.get(f"/api/fixes/{fix_id}", headers=other_headers)
    assert own_fix.status_code == 200
    assert foreign_fix.status_code == 404

    with Session(engine) as db:
        owner = db.scalar(select(User).where(User.email == "owner@example.test"))
        events = list_owned_audit_events(db, owner, 100, 0)
    assert events
    actions = {event.action for event in events}
    assert "owner.event" in actions
    assert "foreign.event" not in actions
    assert "unrelated.event" not in actions


def _approve_for_submission(engine, fix_id):
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        user = db.scalar(select(User).where(User.email == "submission-owner@example.test"))
        fix.status = FixStatus.validation_passed
        digest = proposal_digest(fix)
        fix.validation = {**fix.validation, "proposal_digest": digest}
        db.add(FixReview(fix_id=fix_id, reviewer_id=user.id, reviewer_email=user.email, decision="approved", proposal_digest=digest))
        db.commit()


def test_github_submission_fails_closed_without_account_connection(api_database):
    client, engine = api_database
    owner = _register(client, "submission-owner@example.test")
    other = _register(client, "submission-other@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    _approve_for_submission(engine, fix_id)
    status = client.get(f"/api/fixes/{fix_id}/pr-eligibility", headers=owner)
    assert status.status_code == 200 and status.json()["eligible"] is False
    assert client.get(f"/api/fixes/{fix_id}/pr-eligibility", headers=other).status_code == 404
    with patch("app.api.fixes.create_branch") as create_branch:
        assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=owner).status_code == 503
        create_branch.assert_not_called()


def test_github_submission_rejects_changed_validated_proposal(api_database):
    client, engine = api_database
    owner = _register(client, "submission-owner@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    _approve_for_submission(engine, fix_id)
    with Session(engine) as db:
        db.get(Fix, fix_id).patch += "tampered"
        db.commit()
    with patch("app.api.fixes.create_branch") as create_branch:
        assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=owner).status_code == 409
        create_branch.assert_not_called()


def test_github_submission_unique_claim_blocks_duplicate_without_audit_marker(api_database):
    client, engine = api_database
    owner = _register(client, "submission-owner@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    _approve_for_submission(engine, fix_id)
    with Session(engine) as db:
        fix = db.get(Fix, fix_id)
        finding = db.get(Finding, fix.finding_id)
        repo = db.get(Repo, finding.repo_id)
        db.add(GitHubSubmissionAttempt(fix_id=fix.id, user_id=repo.owner_id, repo_id=repo.id, proposal_digest=proposal_digest(fix), status="started", stage="branch_creation"))
        db.commit()
    with patch("app.api.fixes.require_connected_github"), patch("app.api.fixes.create_branch") as create_branch:
        assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=owner).status_code == 409
        create_branch.assert_not_called()


@pytest.mark.parametrize("status", [FixStatus.pending_review, FixStatus.rejected, FixStatus.validation_failed])
def test_submission_blocks_unapproved_rejected_and_failed_fixes(api_database, status):
    client, engine = api_database
    headers = _register(client, "submission-owner@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    with Session(engine) as db:
        db.get(Fix, fix_id).status = status
        db.commit()
    with patch("app.api.fixes.create_branch") as create_branch:
        assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers).status_code == 409
    create_branch.assert_not_called()


def test_submission_rejects_another_tenant(api_database):
    client, engine = api_database
    _register(client, "submission-owner@example.test")
    other = _register(client, "submission-other@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    _approve_for_submission(engine, fix_id)
    with patch("app.api.fixes.create_branch") as create_branch:
        assert client.post(f"/api/fixes/{fix_id}/open-pr", headers=other).status_code == 404
    create_branch.assert_not_called()


@pytest.mark.parametrize("target", ["../outside.py", "/outside.py", "different.py"])
def test_submission_rejects_invalid_or_mismatched_target(api_database, target):
    client, engine = api_database
    headers = _register(client, "submission-owner@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    _approve_for_submission(engine, fix_id)
    with Session(engine) as db:
        db.get(Fix, fix_id).target_file = target
        db.commit()
    with patch("app.api.fixes.create_branch") as branch:
        response = client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers)
        assert response.status_code == 409
    branch.assert_not_called()


@pytest.mark.parametrize(("failing_stage", "failure"), [
    ("branch_creation", TimeoutError("synthetic")),
    ("branch_creation", GithubException(401, {"message": "synthetic"}, None)),
    ("branch_creation", GithubException(403, {"message": "synthetic"}, None)),
    ("branch_creation", GithubException(429, {"message": "synthetic"}, None)),
    ("file_commit", TimeoutError("synthetic")),
    ("pull_request_creation", TimeoutError("synthetic")),
])
def test_partial_submission_blocks_retry_and_records_safe_stage(api_database, tmp_path, failing_stage, failure):
    client, engine = api_database
    headers = _register(client, "submission-owner@example.test")
    _, fix_id = _seed_fix(engine, "submission-owner@example.test")
    _approve_for_submission(engine, fix_id)
    (tmp_path / "app.py").write_bytes(b"value = 1\n")
    with patch("app.api.fixes.require_connected_github"), patch("app.api.fixes.require_scan_root"), patch("app.api.fixes.clone_repo", return_value=str(tmp_path)), patch(
        "app.api.fixes.validate_scan_path", return_value=tmp_path
    ), patch("app.api.fixes.shutil.rmtree"), patch(
        "app.api.fixes.subprocess.run", return_value=subprocess.CompletedProcess(["git"], 0, stdout=f"{'a' * 40}\n")
    ), patch("app.api.fixes.create_branch", side_effect=failure if failing_stage == "branch_creation" else None) as branch, patch(
        "app.api.fixes.commit_file_changes", side_effect=failure if failing_stage == "file_commit" else None
    ) as commit, patch(
        "app.api.fixes.open_pull_request", side_effect=failure if failing_stage == "pull_request_creation" else None
    ) as pull:
        first = client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers)
        counts = (branch.call_count, commit.call_count, pull.call_count)
        second = client.post(f"/api/fixes/{fix_id}/open-pr", headers=headers)
    assert first.status_code == 502
    assert second.status_code == 409
    assert (branch.call_count, commit.call_count, pull.call_count) == counts
    with Session(engine) as db:
        events = db.scalars(select(AuditLog).where(AuditLog.fix_id == fix_id).order_by(AuditLog.id)).all()
        assert [event.action for event in events] == ["fix.pr_submission_started", "fix.pr_creation_failed"]
        assert events[-1].details["stage"] == failing_stage
        attempt = db.scalar(select(GitHubSubmissionAttempt).where(GitHubSubmissionAttempt.fix_id == fix_id))
        assert attempt.status == "failed" and attempt.stage == failing_stage


def test_osv_alias_overlap_deduplicates_same_advisory_and_preserves_distinct_records(tmp_path):
    (tmp_path / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    ids = ["OSV-A", "OSV-B", "OSV-C"]
    query_response = Mock()
    query_response.json.return_value = {"results": [{"vulns": [{"id": item} for item in ids]}]}
    query_response.raise_for_status.return_value = None

    vulnerabilities = {
        "OSV-A": {
            "id": "OSV-A",
            "aliases": ["GHSA-shared"],
            "summary": "First synthetic advisory",
            "affected": [{
                "package": {"name": "example", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1.0"}]}],
            }],
            "references": [{"url": "https://example.test/a"}],
        },
        "OSV-B": {
            "id": "OSV-B",
            "aliases": ["GHSA-shared", "CVE-2026-1234"],
            "summary": "Alias of first advisory",
            "affected": [{
                "package": {"name": "example", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
            }],
            "references": [{"url": "https://example.test/b"}],
        },
        "OSV-C": {
            "id": "OSV-C",
            "aliases": [],
            "summary": "Distinct synthetic advisory",
            "affected": [{
                "package": {"name": "example", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}],
            }],
            "references": [],
        },
    }

    def detail_response(identifier, **_kwargs):
        response = Mock()
        response.json.return_value = vulnerabilities[identifier.rsplit("/", 1)[-1]]
        response.raise_for_status.return_value = None
        return response

    with patch("app.scanners.deps.httpx.post", return_value=query_response), patch(
        "app.scanners.deps.httpx.get", side_effect=detail_response
    ):
        result = scan_dependencies_with_status(tmp_path)

    assert result.status == "completed"
    assert result.dependencies_queried == 1
    assert len(result.findings) == 2
    merged = next(item for item in result.findings if item["rule_id"] in {"OSV-A", "OSV-B"})
    assert set(merged["aliases"]) == {"OSV-B", "GHSA-shared", "CVE-2026-1234"}
    assert merged["fixed_version"] is None
    assert set(merged["references"]) == {"https://example.test/a", "https://example.test/b"}


def test_scan_history_retains_findings_per_scan_and_reruns_are_idempotent(tmp_path):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        repo = Repo(full_name="owner/history", default_branch="main")
        db.add(repo)
        db.flush()
        scans = [
            Scan(repo_id=repo.id, trigger=ScanTrigger.manual, status=ScanStatus.queued)
            for _ in range(2)
        ]
        db.add_all(scans)
        db.commit()
        scan_ids = [scan.id for scan in scans]

        clone_count = 0

        def clone_checkout(*_args, **_kwargs):
            nonlocal clone_count
            clone_count += 1
            checkout = tmp_path / f"checkout-{clone_count}"
            checkout.mkdir()
            return str(checkout)

        dependency = {
            "type": "dependency",
            "scanner": "osv",
            "file": "requirements.txt",
            "line": None,
            "description": "Synthetic advisory",
            "rule_id": "OSV-HISTORY",
            "advisory_id": "OSV-HISTORY",
            "aliases": [],
            "severity": "high",
            "cvss_score": 7.5,
            "package": "example",
            "ecosystem": "PyPI",
            "installed_version": "1.0.0",
            "affected_versions": "< 1.0.1",
            "fixed_version": "1.0.1",
            "references": [],
        }
        with patch("app.services.scan_service.clone_repo", side_effect=clone_checkout), patch(
            "app.services.scan_service.subprocess.run",
            return_value=subprocess.CompletedProcess(["git"], 0, stdout=f"{'b' * 40}\n"),
        ), patch(
            "app.services.scan_service.scan_repository_secrets",
            return_value=SecretScanResult([], "empty", "gitleaks"),
        ), patch(
            "app.services.scan_service.scan_dependencies_with_status",
            return_value=DependencyScanResult([dependency], "completed", None, 1),
        ), patch(
            "app.services.scan_service.repo_signals",
            return_value={
                "commit_count_90d": 1,
                "contributor_count": 1,
                "env_file_tracked": False,
                "gitignore_has_env": True,
                "has_precommit_secret_hook": True,
                "historical_secret_count": 0,
                "days_since_last_commit": 0,
            },
        ):
            run_scan(db, scan_ids[0])
            run_scan(db, scan_ids[1])
            run_scan(db, scan_ids[0])

        findings_by_scan = dict(
            db.execute(select(Finding.scan_id, func.count(Finding.id)).group_by(Finding.scan_id)).all()
        )
        score_count = db.query(RepoScore).count()
        assert findings_by_scan == {scan_ids[0]: 1, scan_ids[1]: 1}
        assert score_count == 2
    engine.dispose()
