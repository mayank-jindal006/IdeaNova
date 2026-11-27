from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from app.ai.fix import _syntax_check, validate_target_path
from app.ai.models import Finding as ScannerFinding
from app.core.scan_paths import ScanPathError, ScanRootError, require_scan_root, validate_scan_path
from app.db.models import Finding, Fix, Repo
from app.github_client.client import clone_repo
from app.scanners.deps import scan_dependencies_with_status
from app.services.gitleaks import scan_repository_secrets
from app.services.local_remediation import requirements_candidate


def _same_finding_is_present(findings: list[dict], finding: Finding) -> bool:
    if finding.type.value == "secret":
        return any(
            item.file.replace("\\", "/") == finding.file_path
            and item.rule_id == finding.rule_id
            for item in findings
        )
    return any(
        item.get("package") == finding.package
        and item.get("installed_version") == finding.installed_version
        and finding.advisory_id in {item.get("advisory_id"), *item.get("aliases", [])}
        for item in findings
    )


def _secret_finding_signatures(findings: list[ScannerFinding]) -> set[tuple[str, str, str]]:
    return {
        (
            item.file.replace("\\", "/"),
            item.rule_id,
            hashlib.sha256((item.secret or item.match or "").encode("utf-8")).hexdigest(),
        )
        for item in findings
    }


def _dependency_finding_signatures(findings: list[dict]) -> set[tuple[str, str, str, str]]:
    signatures = set()
    for item in findings:
        identifiers = {item.get("advisory_id"), *item.get("aliases", [])}
        signatures.update(
            (item.get("package", ""), item.get("ecosystem", ""), item.get("installed_version", ""), identifier)
            for identifier in identifiers
            if isinstance(identifier, str) and identifier
        )
    return signatures


def validate_fix_candidate(repo: Repo, finding: Finding, fix: Fix) -> dict:
    """Apply a proposal only inside a disposable checkout, then rerun the scanners."""
    checkout_path: str | None = None
    try:
        target_file = validate_target_path(fix.target_file or "")
        if not fix.base_hash or len(fix.edits) != 1 or fix.edits[0].get("file_path") != target_file:
            raise ValueError("Fix proposal metadata is invalid")
        local = bool(repo.local_path)
        if local:
            if os.getenv("REPOGUARD_LOCAL_SCAN_ENABLED", "").lower() != "true" or finding.type.value != "dependency":
                raise ValueError("Local validation is unavailable")
            source = validate_scan_path(repo.local_path)
            checkout_path = tempfile.mkdtemp(prefix="repoguard-validation-", dir=require_scan_root())
            shutil.copytree(source, checkout_path, dirs_exist_ok=True, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        else:
            checkout_path = clone_repo(repo.full_name)
        checkout = validate_scan_path(checkout_path)
        target = (checkout / Path(*target_file.split("/"))).resolve(strict=True)
        if not target.is_relative_to(checkout) or not target.is_file():
            raise ValueError("Fix target is unavailable")
        original_bytes = target.read_bytes()
        if len(original_bytes) > 1_000_000:
            raise ValueError("Fix target is too large")
        if hashlib.sha256(original_bytes).hexdigest() != fix.base_hash:
            return {
                "secret_removed": False,
                "syntax_ok": False,
                "patch_syntax": "failed",
                "target_exists": True,
                "tests": "not_run",
                "security_rescan": "not_run",
                "notes": ["The source file changed after proposal generation; regenerate the proposal."],
            }
        original_bytes.decode("utf-8")
        candidate_content = fix.edits[0].get("new_content")
        if not isinstance(candidate_content, str) or "\x00" in candidate_content:
            raise ValueError("Fix proposal content is invalid")
        if local:
            expected = requirements_candidate(target_file, original_bytes.decode("utf-8"), {
                "package": finding.package, "ecosystem": finding.ecosystem,
                "installed_version": finding.installed_version, "fixed_version": finding.fixed_version,
            })
            if not expected or candidate_content != expected:
                raise ValueError("Fix proposal does not match the recorded advisory")
        syntax_ok, syntax_notes = _syntax_check(target_file, candidate_content)

        before_secrets = scan_repository_secrets(checkout, working_tree=True) if local else scan_repository_secrets(checkout)
        before_dependencies = scan_dependencies_with_status(checkout)
        target.write_text(candidate_content, encoding="utf-8", newline="")
        after_secrets = scan_repository_secrets(checkout, working_tree=True) if local else scan_repository_secrets(checkout)
        after_dependencies = scan_dependencies_with_status(checkout)

        if finding.type.value == "secret":
            before_present = any(
                item.file.replace("\\", "/") == finding.file_path and item.rule_id == finding.rule_id
                for item in before_secrets.findings
            )
            after_present = any(
                item.file.replace("\\", "/") == finding.file_path and item.rule_id == finding.rule_id
                for item in after_secrets.findings
            )
            finding_removed = before_present and not after_present
            scanners_completed = (
                before_secrets.source == after_secrets.source == "gitleaks"
                and before_secrets.status in {"completed", "empty"}
                and after_secrets.status in {"completed", "empty"}
            )
            secret_removed = finding_removed
        else:
            before_present = _same_finding_is_present(before_dependencies.findings, finding)
            after_present = _same_finding_is_present(after_dependencies.findings, finding)
            finding_removed = before_present and not after_present
            secret_removed = False

        secret_scans_completed = (
            before_secrets.source == after_secrets.source == "gitleaks"
            and before_secrets.status in {"completed", "empty"}
            and after_secrets.status in {"completed", "empty"}
        )
        no_new_secrets = _secret_finding_signatures(after_secrets.findings) <= _secret_finding_signatures(before_secrets.findings)
        dependency_scans_completed = (
            before_dependencies.status in {"completed", "empty"}
            and after_dependencies.status in {"completed", "empty"}
        )
        scanners_completed = secret_scans_completed and dependency_scans_completed
        no_new_findings = _dependency_finding_signatures(after_dependencies.findings) <= _dependency_finding_signatures(
            before_dependencies.findings
        )
        validation_passed = finding_removed and scanners_completed and no_new_findings and no_new_secrets and syntax_ok
        notes = [
            *syntax_notes,
            "The original repository was not modified; validation ran in a disposable checkout.",
            "Repository tests were not run because they execute untrusted repository code.",
        ]
        if not before_present:
            notes.append("The reported finding was not reproduced in the checked-out source.")
        if after_present:
            notes.append("The reported finding remains after applying the proposal.")
        if not scanners_completed:
            notes.append("A required scanner was unavailable or returned an incomplete result.")
        if not no_new_secrets or not no_new_findings:
            notes.append("The proposal introduced or exposed additional security findings.")
        return {
            "secret_removed": secret_removed,
            "syntax_ok": syntax_ok,
            "patch_syntax": "passed",
            "target_exists": True,
            "tests": "not_run",
            "security_rescan": "passed" if validation_passed else "failed",
            "notes": notes,
        }
    except (OSError, UnicodeDecodeError, ScanPathError, ScanRootError, ValueError, RuntimeError):
        return {
            "secret_removed": False,
            "syntax_ok": False,
            "patch_syntax": "failed",
            "target_exists": False,
            "tests": "not_run",
            "security_rescan": "failed",
            "notes": ["The proposal could not be safely validated in a disposable checkout."],
        }
    finally:
        if checkout_path:
            shutil.rmtree(checkout_path, ignore_errors=True)
