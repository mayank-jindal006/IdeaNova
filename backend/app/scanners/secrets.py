"""Database persistence adapter for the canonical Gitleaks scanner.

Execution lives exclusively in :mod:`app.services.gitleaks`.  This module
converts its normalized, in-memory findings into the existing ORM payload
shape without retaining raw secret material.
"""
from __future__ import annotations

import hashlib

from app.services.gitleaks import SecretScanResult, scan_repository_secrets


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}****{value[-4:]}"


def secret_scan_to_persistence(scan: SecretScanResult) -> list[dict]:
    """Convert canonical scanner output to DB-safe finding dictionaries."""
    results: list[dict] = []
    for finding in scan.findings:
        secret = finding.secret or finding.match
        if not secret:
            continue
        results.append({
            "type": "secret",
            "scanner": scan.source,
            "rule_id": finding.rule_id or "gitleaks-secret",
            "title": finding.description or finding.rule_id or "Secret finding",
            "severity": finding.severity or "high",
            "file_path": finding.file,
            "line": finding.line or finding.start_line,
            "commit_sha": None,
            "secret_masked": _mask(secret),
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "package": None,
            "ecosystem": None,
            "installed_version": None,
            "affected_versions": None,
            "fixed_version": None,
            "advisory_id": None,
            "aliases": [],
            "references": [],
            "cvss_score": None,
            "in_history_only": False,
            "confidence": 0.92 if scan.source == "gitleaks" else 0.65,
            "status": "open",
        })
    return results


def scan_secrets(repo_path: str, include_history: bool = True) -> list[dict]:
    """Compatibility adapter; delegates execution to the canonical scanner."""
    return secret_scan_to_persistence(scan_repository_secrets(repo_path, include_history))


__all__ = ["scan_secrets", "secret_scan_to_persistence"]
