from __future__ import annotations

import hashlib
import hmac
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

from github import Github

from app.core.scan_paths import require_scan_root, validate_scan_path
from app.settings import settings

_GITHUB_FULL_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]+$")


def _github() -> Github:
    if not settings.github_token:
        raise RuntimeError("GITHUB_TOKEN is not configured")
    return Github(settings.github_token)


def default_branch(full_name: str) -> str:
    return _github().get_repo(full_name).default_branch


def clone_repo(full_name: str) -> str:
    """Clone complete history into a validated server-managed checkout."""
    if not _GITHUB_FULL_NAME.fullmatch(full_name):
        raise ValueError("Repository name is invalid")
    root = require_scan_root()
    target = Path(tempfile.mkdtemp(prefix="repoguard-", dir=root))
    url = f"https://x-access-token:{quote(settings.github_token or '', safe='')}@github.com/{full_name}.git"
    try:
        subprocess.run(["git", "clone", url, str(target)], check=True, capture_output=True, text=True)
        return str(validate_scan_path(target))
    except subprocess.CalledProcessError:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError("Repository checkout failed") from None
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def create_branch(full_name: str, branch: str, base_branch: str) -> None:
    repo = _github().get_repo(full_name)
    source = repo.get_branch(base_branch)
    repo.create_git_ref(ref=f"refs/heads/{branch}", sha=source.commit.sha)


def commit_file_changes(full_name: str, branch: str, edits: list[dict]) -> None:
    repo = _github().get_repo(full_name)
    for edit in edits:
        path, content = edit["file_path"], edit["new_content"]
        try:
            existing = repo.get_contents(path, ref=branch)
            repo.update_file(path, f"RepoGuard remediation for {path}", content, existing.sha, branch=branch)
        except Exception as exc:
            if getattr(exc, "status", None) != 404:
                raise
            repo.create_file(path, f"RepoGuard remediation for {path}", content, branch=branch)


def open_pull_request(full_name: str, branch: str, base_branch: str, title: str, body: str) -> tuple[str, int]:
    pull = _github().get_repo(full_name).create_pull(title=title, body=body, head=branch, base=base_branch)
    return pull.html_url, pull.number


def verify_webhook_signature(payload: bytes, signature: str | None) -> bool:
    if not settings.github_webhook_secret or not signature:
        return False
    expected = "sha256=" + hmac.new(settings.github_webhook_secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def repo_signals(repo_path: str) -> dict:
    root = Path(repo_path)
    gitignore = (root / ".gitignore").read_text(encoding="utf-8", errors="ignore") if (root / ".gitignore").exists() else ""
    commits = subprocess.run(["git", "-C", repo_path, "rev-list", "--count", "--since=90.days", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    contributors = subprocess.run(["git", "-C", repo_path, "shortlog", "-sne", "HEAD"], capture_output=True, text=True, check=False).stdout.splitlines()
    last_commit = subprocess.run(["git", "-C", repo_path, "log", "-1", "--format=%ct"], capture_output=True, text=True, check=False).stdout.strip()
    import time
    return {"commit_count_90d": int(commits or 0), "contributor_count": len(contributors), "env_file_tracked": bool(subprocess.run(["git", "-C", repo_path, "ls-files", ".env"], capture_output=True, text=True).stdout.strip()), "gitignore_has_env": ".env" in gitignore, "has_precommit_secret_hook": (root / ".git" / "hooks" / "pre-commit").exists(), "historical_secret_count": 0, "days_since_last_commit": int((time.time() - int(last_commit)) / 86400) if last_commit else 0}
