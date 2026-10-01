import hashlib
import json
import subprocess
from pathlib import Path

from app.config import get_settings


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:4]}****{value[-4:]}"


def _finding(report: dict, repo_path: Path, history: bool) -> dict:
    secret = report.get("Secret", "")
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    rule_id = report.get("RuleID", "gitleaks")
    file_path = report.get("File", "")
    try:
        file_path = str(Path(file_path).resolve().relative_to(repo_path.resolve())).replace("\\", "/")
    except ValueError:
        file_path = file_path.replace("\\", "/")
    start_column = end_column = None
    try:
        line_text = (
            repo_path / file_path
        ).read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()[report["StartLine"] - 1]
        idx = line_text.find(secret)
        start_column = idx + 1 if idx >= 0 else None
        end_column = idx + len(secret) if idx >= 0 else None
    except (IndexError, KeyError, OSError):
        # Historical findings can refer to files or lines no longer present at HEAD.
        pass
    fingerprint = hashlib.sha256(f"{rule_id}{file_path}{secret_hash}".encode()).hexdigest()
    return {
        "type": "secret", "rule_id": rule_id, "title": report.get("Description") or f"Secret detected by {rule_id}",
        "severity": "high", "file_path": file_path, "line": report.get("StartLine"),
        "start_column": start_column, "end_column": end_column,
        "commit_sha": report.get("Commit") or None, "secret_masked": _mask(secret), "secret_hash": secret_hash,
        "package": None, "ecosystem": None, "installed_version": None, "fixed_version": None,
        "in_history_only": history, "confidence": 1.0, "status": "open", "owasp_ids": [], "asvs_ids": [],
        "fingerprint": fingerprint,
    }


def _run(args: list[str]) -> list[dict]:
    completed = subprocess.run(args, capture_output=True, text=True, check=False, timeout=180)
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or "Gitleaks failed")
    report = Path(args[args.index("--report-path") + 1])
    if not report.exists() or not report.read_text(encoding="utf-8").strip():
        return []
    return json.loads(report.read_text(encoding="utf-8"))


def scan_secrets(repo_path: str, include_history: bool = True) -> list[dict]:
    root = Path(repo_path)
    report_path = root / ".repoguard-gitleaks.json"
    settings = get_settings()
    try:
        head_reports = _run([settings.gitleaks_bin, "dir", str(root), "--report-format", "json", "--report-path", str(report_path), "--no-banner"])
        seen = {_finding(item, root, False)["fingerprint"] for item in head_reports}
        findings = [_finding(item, root, False) for item in head_reports]
        if include_history:
            history_reports = _run([settings.gitleaks_bin, "git", str(root), "--report-format", "json", "--report-path", str(report_path), "--no-banner"])
            for item in history_reports:
                parsed = _finding(item, root, True)
                if parsed["fingerprint"] not in seen:
                    findings.append(parsed)
        return findings
    finally:
        report_path.unlink(missing_ok=True)
