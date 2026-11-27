"""Build a narrow, independently verifiable patch without modifying a checkout."""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from app.ai.redaction import redact_context_for_llm
from app.core.scan_paths import validate_scan_path
from app.db.models import FindingStatus, FindingType, FixStatus
from app.services.local_remediation import requirements_candidate
from app.services.proposal_integrity import proposal_digest

MAX_BYTES = 128 * 1024
_PATH = re.compile(r"(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*requirements\.txt\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class ExportRejected(ValueError):
    pass


def build_export(fix, finding, repo, review, user, latest_fix_id):
    """Return a ZIP, or reject without exposing source details."""
    if not repo.local_path or os.getenv("REPOGUARD_LOCAL_SCAN_ENABLED", "").lower() != "true":
        raise ExportRejected("Export is available only for enabled local repositories")
    if finding.type != FindingType.dependency or finding.status not in {FindingStatus.open, FindingStatus.fix_proposed}:
        raise ExportRejected("Finding is not eligible for export")
    if fix.id != latest_fix_id or fix.status != FixStatus.validation_passed:
        raise ExportRejected("The latest proposal must have passed validation")
    if not isinstance(fix.patch, str) or len(fix.patch.encode("utf-8")) > MAX_BYTES or not isinstance(fix.edits, list) or len(fix.edits) != 1 or not isinstance(fix.edits[0], dict):
        raise ExportRejected("The stored proposal is invalid or too large")
    if set(fix.edits[0]) != {"file_path", "new_content"} or not isinstance(fix.edits[0].get("new_content"), str) or len(fix.edits[0]["new_content"].encode("utf-8")) > MAX_BYTES:
        raise ExportRejected("The stored proposal is invalid or too large")
    digest = proposal_digest(fix)
    validation = fix.validation if isinstance(fix.validation, dict) else {}
    if not review or review.decision != "approved" or review.reviewer_id != user.id or not isinstance(review.proposal_digest, str) or not hmac.compare_digest(review.proposal_digest, digest):
        raise ExportRejected("Approval does not match the current proposal")
    if not isinstance(validation.get("proposal_digest"), str) or not hmac.compare_digest(validation["proposal_digest"], digest) or validation.get("security_rescan") != "passed" or validation.get("patch_syntax") != "passed" or validation.get("target_exists") is not True or validation.get("syntax_ok") is not True:
        raise ExportRejected("Validation does not match the current proposal")
    path = fix.target_file
    if not isinstance(path, str) or len(path) > 1024 or not _PATH.fullmatch(path) or any(part in {".", ".."} for part in path.split("/")):
        raise ExportRejected("The proposal target is not supported")
    if finding.file_path != path or not isinstance(fix.base_hash, str) or not _HASH.fullmatch(fix.base_hash):
        raise ExportRejected("The proposal source metadata is invalid")
    if fix.edits[0].get("file_path") != path:
        raise ExportRejected("Only one validated file is supported")
    candidate = fix.edits[0].get("new_content")
    if not isinstance(candidate, str) or len(candidate.encode("utf-8")) > MAX_BYTES:
        raise ExportRejected("The proposed content is invalid or too large")
    try:
        checkout = validate_scan_path(repo.local_path)
        target = checkout
        for part in path.split("/"):
            target = target / part
            if target.is_symlink() or target.is_junction():
                raise ExportRejected("Linked targets are not supported")
        target = target.resolve(strict=True)
        if not target.is_relative_to(checkout) or not target.is_file() or target.stat().st_size > MAX_BYTES:
            raise ExportRejected("The proposal source is unavailable or too large")
        with target.open("rb") as source_file:
            source_bytes = source_file.read(MAX_BYTES + 1)
        source = source_bytes.decode("utf-8")
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        if isinstance(exc, ExportRejected):
            raise
        raise ExportRejected("The proposal source is unavailable") from None
    if len(source_bytes) > MAX_BYTES or hashlib.sha256(source_bytes).hexdigest() != fix.base_hash:
        raise ExportRejected("The source changed since proposal generation")
    if redact_context_for_llm(source, []) != source or redact_context_for_llm(candidate, []) != candidate:
        raise ExportRejected("The proposal contains sensitive material")
    expected = requirements_candidate(path, source, {"package": finding.package, "ecosystem": finding.ecosystem, "installed_version": finding.installed_version, "fixed_version": finding.fixed_version})
    if expected is None or candidate != expected or len(source.splitlines()) != 1 or not source.endswith("\n") or not candidate.endswith("\n"):
        raise ExportRejected("The proposed change is not supported")
    patch = "".join(difflib.unified_diff(source.splitlines(keepends=True), candidate.splitlines(keepends=True), fromfile=f"a/{path}", tofile=f"b/{path}"))
    if not patch or patch != fix.patch or len(patch.encode("utf-8")) > MAX_BYTES or redact_context_for_llm(patch, []) != patch:
        raise ExportRejected("The stored patch cannot be exported safely")
    patch_bytes = patch.encode("utf-8")
    patch_hash = hashlib.sha256(patch_bytes).hexdigest()
    proposal = {"finding_id": fix.finding_id, "target_file": fix.target_file, "base_hash": fix.base_hash, "patch": fix.patch, "edits": fix.edits}
    manifest = {"schema_version": 1, "finding_id": finding.id, "proposal_id": fix.id, "proposal_digest": digest, "validated_proposal_digest": validation["proposal_digest"], "approval_digest": review.proposal_digest, "original_source_sha256": fix.base_hash, "target_path": path, "remediation_type": "pypi_exact_pin", "patch_sha256": patch_hash, "created_at": datetime.now(timezone.utc).isoformat(), "validation_status": "security_rescan_passed_tests_not_asserted", "statement": "Export is not application or proof of remediation; repository tests may not have run.", "proposal": proposal}
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("remediation.patch", patch_bytes)
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
    return output.getvalue(), manifest
