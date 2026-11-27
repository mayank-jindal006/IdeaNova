import difflib
import hashlib
import io
import json
import os
import subprocess
import zipfile
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core import scan_paths
from app.core.config import settings
from app.db.base import Base
from app.db.models import AuditLog, Finding, FindingStatus, FindingType, Fix, FixReview, FixStatus, FixTier, Repo, Scan, ScanStatus, ScanTrigger, User
from app.db.session import get_db
from app.main import create_app
from app.services.proposal_integrity import proposal_digest


@pytest.fixture
def export_case(tmp_path, monkeypatch):
    root = tmp_path / 'root'; root.mkdir()
    checkout = root / 'repo'; checkout.mkdir()
    target = checkout / 'requirements.txt'; target.write_bytes(b'requests==2.19.1\n')
    monkeypatch.setattr(scan_paths, 'settings', replace(settings, scan_root=root))
    monkeypatch.setenv('REPOGUARD_LOCAL_SCAN_ENABLED', 'true')
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    app = create_app()
    def test_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = test_db
    with TestClient(app) as client:
        def register(email):
            r = client.post('/api/auth/register', json={'email': email, 'password': 'synthetic-password-only'})
            assert r.status_code == 200
            return {'Authorization': 'Bearer ' + r.json()['access_token']}
        owner = register('export-owner@example.invalid'); other = register('export-other@example.invalid')
        with Session(engine) as db:
            user = db.scalar(select(User).where(User.email == 'export-owner@example.invalid'))
            repo = Repo(owner_id=user.id, local_path=str(checkout), full_name='local/export-test', default_branch='main'); db.add(repo); db.flush()
            scan = Scan(repo_id=repo.id, trigger=ScanTrigger.manual, status=ScanStatus.done); db.add(scan); db.flush()
            finding = Finding(scan_id=scan.id, repo_id=repo.id, fingerprint='fixture', type=FindingType.dependency, rule_id='OSV-TEST', title='Synthetic advisory', severity=None, scanner='osv', file_path='requirements.txt', package='requests', ecosystem='PyPI', installed_version='2.19.1', fixed_version='2.32.4', advisory_id='OSV-TEST', aliases=[], references=[], in_history_only=False, confidence=0.9, status=FindingStatus.fix_proposed, owasp_ids=[], asvs_ids=[]); db.add(finding); db.flush()
            before='requests==2.19.1\n'; after='requests==2.32.4\n'; diff=''.join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile='a/requirements.txt', tofile='b/requirements.txt'))
            fix = Fix(finding_id=finding.id, explanation={'what':'Synthetic', 'why_dangerous':'Synthetic', 'how_fixed':'Synthetic', 'rotation_required':False, 'rotation_note':'None'}, edits=[{'file_path':'requirements.txt','new_content':after}], patch=diff, target_file='requirements.txt', base_hash=hashlib.sha256(before.encode()).hexdigest(), tier=FixTier.pr_review, validation={}, status=FixStatus.validation_passed); db.add(fix); db.flush()
            digest=proposal_digest(fix); fix.validation={'proposal_digest':digest,'security_rescan':'passed','patch_syntax':'passed','target_exists':True,'syntax_ok':True,'tests':'not_run','secret_removed':False,'notes':[]}; db.add(FixReview(fix_id=fix.id, reviewer_id=user.id, reviewer_email=user.email, decision='approved', proposal_digest=digest)); db.commit(); fix_id=fix.id
        yield client, engine, owner, other, target, fix_id
    engine.dispose()


def test_export_archive_manifest_audit_and_original_integrity(export_case, monkeypatch):
    client, engine, owner, _, target, fix_id = export_case
    monkeypatch.setattr('subprocess.run', lambda *a, **k: pytest.fail('export must not run subprocesses'))
    assert client.get(f'/api/fixes/{fix_id}/export-status', headers=owner).json()['eligible'] is True
    first=client.post(f'/api/fixes/{fix_id}/export', headers=owner); second=client.post(f'/api/fixes/{fix_id}/export', headers=owner)
    assert first.status_code == second.status_code == 200
    assert first.headers['content-type'] == 'application/zip'
    with zipfile.ZipFile(io.BytesIO(first.content)) as z, zipfile.ZipFile(io.BytesIO(second.content)) as z2:
        patch=z.read('remediation.patch'); manifest=json.loads(z.read('manifest.json'))
        assert patch == z2.read('remediation.patch')
        assert hashlib.sha256(patch).hexdigest() == manifest['patch_sha256']
        canonical=json.dumps(manifest['proposal'], sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        assert hashlib.sha256(canonical.encode()).hexdigest() == manifest['proposal_digest'] == manifest['approval_digest'] == manifest['validated_proposal_digest']
    assert target.read_bytes() == b'requests==2.19.1\n'
    with Session(engine) as db:
        assert len(db.scalars(select(AuditLog).where(AuditLog.action == 'fix.exported')).all()) == 2


@pytest.mark.parametrize('change', ['patch', 'approval', 'validation', 'status', 'path', 'drive', 'unc', 'oversized', 'oversized_source', 'stale', 'missing_review'])
def test_export_rejects_ineligible_proposals(export_case, change):
    client, engine, owner, _, target, fix_id = export_case
    with Session(engine) as db:
        fix=db.get(Fix, fix_id); review=db.scalar(select(FixReview).where(FixReview.fix_id == fix_id))
        if change == 'patch': fix.patch += 'tampered'
        elif change == 'approval': review.proposal_digest = '0' * 64
        elif change == 'validation': fix.validation = {**fix.validation, 'proposal_digest':'0' * 64}
        elif change == 'status': fix.status = FixStatus.approved
        elif change == 'path': fix.target_file = '../requirements.txt'
        elif change == 'drive': fix.target_file = 'C:/requirements.txt'
        elif change == 'unc': fix.target_file = r'\\server\share\requirements.txt'
        elif change == 'oversized': fix.patch = 'x' * (128 * 1024 + 1)
        elif change == 'oversized_source': target.write_bytes(b'x' * (128 * 1024 + 1))
        elif change == 'stale': target.write_bytes(b'requests==2.20.0\n')
        else: review.decision = 'rejected'
        db.commit()
    response=client.post(f'/api/fixes/{fix_id}/export', headers=owner)
    assert response.status_code == 409
    with Session(engine) as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == 'fix.export_rejected')) is not None


def test_export_rejects_other_tenant_and_missing_auth(export_case):
    client, _, _, other, _, fix_id = export_case
    assert client.post(f'/api/fixes/{fix_id}/export').status_code == 401
    assert client.post(f'/api/fixes/{fix_id}/export', headers=other).status_code == 404


@pytest.mark.parametrize('path', ['../requirements.txt', 'C:/requirements.txt', r'\\server\share\requirements.txt', 'dir//requirements.txt', 'requirements.txt\n--- a/other'])
def test_export_rejects_invalid_path_even_if_digests_match(export_case, path):
    client, engine, owner, _, _, fix_id = export_case
    with Session(engine) as db:
        fix=db.get(Fix, fix_id); fix.target_file=path; fix.edits=[{'file_path':path,'new_content':'requests==2.32.4\n'}]
        db.get(Finding, fix.finding_id).file_path=path
        digest=proposal_digest(fix); fix.validation={**fix.validation,'proposal_digest':digest}
        db.scalar(select(FixReview).where(FixReview.fix_id == fix_id)).proposal_digest=digest
        db.commit()
    assert client.post(f'/api/fixes/{fix_id}/export', headers=owner).status_code == 409


def test_export_rejects_forged_patch_even_if_digests_match(export_case):
    client, engine, owner, _, _, fix_id = export_case
    with Session(engine) as db:
        fix=db.get(Fix, fix_id); fix.patch += '+ghp_' + 'A' * 36 + '\n'
        digest=proposal_digest(fix); fix.validation={**fix.validation,'proposal_digest':digest}
        db.scalar(select(FixReview).where(FixReview.fix_id == fix_id)).proposal_digest=digest
        db.commit()
    assert client.post(f'/api/fixes/{fix_id}/export', headers=owner).status_code == 409


def test_export_rejects_superseded_proposal(export_case):
    client, engine, owner, _, _, fix_id = export_case
    with Session(engine) as db:
        fix=db.get(Fix, fix_id)
        newer=Fix(finding_id=fix.finding_id, explanation=fix.explanation, edits=[], patch=None, tier=FixTier.flag_only, validation=fix.validation, status=FixStatus.generated)
        db.add(newer); db.commit()
    assert client.post(f'/api/fixes/{fix_id}/export', headers=owner).status_code == 409


def test_export_rejects_secret_in_unchanged_manifest_content(export_case):
    client, engine, owner, _, target, fix_id = export_case
    unchanged = 'ghp_' + 'A' * 36 + '==1.0\n' + 'safe==1.0\n' * 8
    source = unchanged + 'requests==2.19.1\n'; candidate = unchanged + 'requests==2.32.4\n'
    target.write_bytes(source.encode())
    with Session(engine) as db:
        fix=db.get(Fix, fix_id); fix.base_hash=hashlib.sha256(source.encode()).hexdigest()
        fix.edits=[{'file_path':'requirements.txt','new_content':candidate}]
        fix.patch=''.join(difflib.unified_diff(source.splitlines(keepends=True), candidate.splitlines(keepends=True), fromfile='a/requirements.txt', tofile='b/requirements.txt'))
        digest=proposal_digest(fix); fix.validation={**fix.validation,'proposal_digest':digest}
        db.scalar(select(FixReview).where(FixReview.fix_id == fix_id)).proposal_digest=digest
        db.commit()
    assert client.post(f'/api/fixes/{fix_id}/export', headers=owner).status_code == 409


def test_export_rejects_junction_escape(export_case, tmp_path):
    client, engine, owner, _, target, fix_id = export_case
    outside=tmp_path / 'outside'; outside.mkdir(); (outside / 'requirements.txt').write_bytes(target.read_bytes())
    link=target.parent / 'escape'
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != 'nt': pytest.skip('symbolic links unavailable')
        result=subprocess.run(['cmd','/d','/c','mklink','/J',str(link),str(outside)],capture_output=True,check=False)
        if result.returncode: pytest.skip('junctions unavailable')
    with Session(engine) as db:
        fix=db.get(Fix, fix_id); fix.target_file='escape/requirements.txt'; db.get(Finding,fix.finding_id).file_path=fix.target_file
        fix.edits=[{'file_path':fix.target_file,'new_content':'requests==2.32.4\n'}]
        digest=proposal_digest(fix); fix.validation={**fix.validation,'proposal_digest':digest}
        db.scalar(select(FixReview).where(FixReview.fix_id == fix_id)).proposal_digest=digest
        db.commit()
    assert client.post(f'/api/fixes/{fix_id}/export', headers=owner).status_code == 409
