from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from app.ai.models import Finding
from app.core.config import settings
from app.core.scan_paths import validate_scan_path
from app.settings import settings as runtime_settings

_GITLEAKS_PATTERNS = [
    ("aws-access-token", r"AKIA[0-9A-Z]{16}"),
    ("github-pat", r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    ("google-api-key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("generic-api-key", r"(?i)(?:api[_-]?key|token|secret)[=:]\s*[\"']?[A-Za-z0-9_\-]{12,}[\"']?"),
    ("db-password", r"(?i)(?:DB|DATABASE|PASSWORD|PWD)[_=:-]\s*[\"']?[A-Za-z0-9!@#$%^&*()_\-+=]{8,}[\"']?"),
]


def _normalize_raw_finding(item: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    file_value = item.get("file") or item.get("File") or item.get("path") or item.get("Path")
    if file_value is not None:
        normalized["file"] = str(file_value)

    description = item.get("description") or item.get("Description")
    if description is not None:
        normalized["description"] = str(description)

    secret_value = item.get("secret") or item.get("Secret") or item.get("match") or item.get("Match")
    if secret_value is not None:
        normalized["secret"] = str(secret_value)
        normalized["match"] = str(secret_value)

    rule_id = item.get("rule_id") or item.get("RuleID") or item.get("ruleId") or item.get("RuleId")
    if rule_id is not None:
        normalized["rule_id"] = str(rule_id)

    severity = item.get("severity") or item.get("Severity")
    if severity is not None:
        normalized["severity"] = str(severity)

    for key in ("StartLine", "start_line", "line", "Line"):
        if key in item:
            normalized["start_line"] = int(item[key])
            break

    for key in ("EndLine", "end_line"):
        if key in item:
            normalized["end_line"] = int(item[key])
            break

    for key in ("StartColumn", "start_column"):
        if key in item:
            normalized["start_column"] = int(item[key])
            break

    for key in ("EndColumn", "end_column"):
        if key in item:
            normalized["end_column"] = int(item[key])
            break

    if "start_line" not in normalized and "line" in item:
        normalized["start_line"] = int(item["line"])
    if "line" not in normalized and "start_line" in normalized:
        normalized["line"] = normalized["start_line"]
    if "end_line" not in normalized and "start_line" in normalized:
        normalized["end_line"] = normalized["start_line"]
    if "start_column" not in normalized and "end_column" in normalized:
        normalized["start_column"] = 1

    return normalized


def parse_gitleaks_report(report: str | bytes | dict[str, Any] | list[dict[str, Any]]) -> list[Finding]:
    """Parse a Gitleaks JSON report into validated Finding objects."""
    if isinstance(report, (str, bytes)):
        try:
            payload = report.decode("utf-8") if isinstance(report, bytes) else report.strip()
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid Gitleaks report encoding") from exc
        if not payload:
            return []
        try:
            report_obj = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid Gitleaks report JSON") from exc
    else:
        report_obj = report

    if isinstance(report_obj, list):
        findings_payload = report_obj
    elif isinstance(report_obj, dict):
        report_key = next(
            (key for key in ("Findings", "findings", "results", "Results") if key in report_obj),
            None,
        )
        if report_key is None:
            raise ValueError("Gitleaks report does not contain a findings list")
        findings_payload = report_obj[report_key]
        if findings_payload is None:
            findings_payload = []
    else:
        raise ValueError("Gitleaks report must be a JSON array or object")

    if not isinstance(findings_payload, list):
        raise ValueError("Gitleaks findings must be a JSON array")

    findings: list[Finding] = []
    for item in findings_payload:
        if not isinstance(item, dict):
            raise ValueError("Gitleaks report contains an invalid finding")
        normalized = _normalize_raw_finding(item)
        if not normalized.get("file"):
            normalized["file"] = item.get("File") or item.get("file") or "unknown"
        findings.append(Finding.model_validate(normalized))
    return findings


def _line_and_column_for_index(text: str, index: int) -> tuple[int, int]:
    if index < 0:
        index = 0
    line_start = text.rfind("\n", 0, index)
    line = text.count("\n", 0, index) + 1
    col = index - (line_start + 1) + 1
    return line, col


_SKIPPED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}


@dataclass(frozen=True, slots=True)
class SecretScanResult:
    findings: list[Finding]
    status: str
    source: str
    reason: str | None = None


def _fallback_scan(repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()

    for path in sorted(repo_root.rglob("*")):
        if not path.is_file() or _SKIPPED_DIRECTORIES.intersection(path.relative_to(repo_root).parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf"}:
            continue

        try:
            if path.stat().st_size > settings.max_scan_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for rule_id, pattern in _GITLEAKS_PATTERNS:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                secret = match.group(0)
                start_index = match.start()
                line_number, col = _line_and_column_for_index(text, start_index)
                end_col = col + len(secret) - 1
                if secret.startswith("api") and "=" not in secret:
                    continue
                key = (str(path), line_number, col, secret)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        file=str(path.relative_to(repo_root)),
                        line=line_number,
                        description=f"{rule_id} detected in {path.name}",
                        secret=secret,
                        match=secret,
                        rule_id=rule_id,
                        severity="critical" if "token" in rule_id or "secret" in rule_id else "high",
                        start_line=line_number,
                        end_line=line_number,
                        start_column=col,
                        end_column=end_col,
                    )
                )

    return findings


def _discover_gitleaks_binary() -> tuple[str | None, str | None]:
    configured_binary = os.getenv("GITLEAKS_BIN", "").strip()
    if configured_binary:
        configured_path = Path(configured_binary).expanduser()
        if configured_path.is_file():
            return str(configured_path.resolve()), None
        if configured_path.is_absolute() or configured_path.parent != Path("."):
            return None, "gitleaks_configured_binary_unavailable"

        resolved_command = shutil.which(configured_binary)
        if resolved_command:
            return resolved_command, None
        return None, "gitleaks_configured_binary_unavailable"

    for executable in ("gitleaks", "gitleaks.exe"):
        resolved_command = shutil.which(executable)
        if resolved_command:
            return resolved_command, None
    return None, "gitleaks_binary_unavailable"


def _regex_fallback(repo_root: Path, reason: str) -> SecretScanResult:
    return SecretScanResult(_fallback_scan(repo_root), "fallback", "regex_fallback", reason)


def _completed_result(findings: list[Finding]) -> SecretScanResult:
    return SecretScanResult(findings, "completed" if findings else "empty", "gitleaks")


def scan_repository_secrets(repo_path: str | Path, include_history: bool = False, *, working_tree: bool = False) -> SecretScanResult:
    """Run the Gitleaks binary when available, with an explicitly labelled regex fallback."""
    repo_root = validate_scan_path(repo_path)

    gitleaks_path, discovery_error = _discover_gitleaks_binary()
    if not gitleaks_path:
        return _regex_fallback(repo_root, discovery_error or "gitleaks_binary_unavailable")

    # TemporaryDirectory guarantees raw reports do not accumulate on disk.
    with tempfile.TemporaryDirectory(prefix="repoguard-") as temp_dir:
        report_path = Path(temp_dir) / "gitleaks-report.json"
        command = [
            gitleaks_path, "detect", "--source", str(repo_root), "--report-format", "json",
            "--report-path", str(report_path), "--exit-code", "1", "--no-banner",
        ]
        if working_tree:
            command.append("--no-git")
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=runtime_settings.scan_timeout_seconds,
                cwd=repo_root,
            )
        except subprocess.TimeoutExpired:
            return _regex_fallback(repo_root, "gitleaks_timeout")
        except OSError:
            return _regex_fallback(repo_root, "gitleaks_execution_failed")

        # Gitleaks uses exit code 1 when leaks are found. Any other nonzero exit is a tool failure.
        if completed.returncode not in (0, 1):
            return _regex_fallback(repo_root, "gitleaks_nonzero_exit")
        try:
            if not report_path.exists():
                return _regex_fallback(repo_root, "gitleaks_report_missing")
            if report_path.stat().st_size == 0:
                findings = []
            else:
                findings = parse_gitleaks_report(report_path.read_text(encoding="utf-8"))
        except OSError:
            return _regex_fallback(repo_root, "gitleaks_report_unreadable")
        except (TypeError, UnicodeDecodeError, ValueError):
            return _regex_fallback(repo_root, "gitleaks_invalid_report")
        if completed.returncode == 1 and not findings:
            return _regex_fallback(repo_root, "gitleaks_exit_code_inconsistent")
        return _completed_result(findings)


def scan_repository(repo_path: str | Path, include_history: bool = False) -> list[Finding]:
    """Compatibility entry point returning only secret findings."""
    return scan_repository_secrets(repo_path, include_history).findings


__all__ = ["SecretScanResult", "parse_gitleaks_report", "scan_repository", "scan_repository_secrets"]
