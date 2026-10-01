import hashlib
import hmac
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from github import Github

from app.config import get_settings


def _github() -> Github:
    token = get_settings().github_token
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not configured")
    return Github(token)


def clone_repo(full_name: str) -> str:
    token = get_settings().github_token
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not configured")
    destination = tempfile.mkdtemp(prefix="repoguard-")
    url = f"https://x-access-token:{token}@github.com/{full_name}.git"
    completed = subprocess.run(["git", "clone", url, destination], capture_output=True, text=True, check=False, timeout=180)
    if completed.returncode:
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError(completed.stderr.strip() or "Repository clone failed")
    return destination


def get_default_branch(full_name: str) -> str:
    return _github().get_repo(full_name).default_branch


def cleanup_clone(repo_path: str) -> None:
    shutil.rmtree(repo_path, ignore_errors=True)


def create_branch(full_name: str, branch_name: str, base_branch: str) -> None:
    repository = _github().get_repo(full_name)
    sha = repository.get_branch(base_branch).commit.sha
    repository.create_git_ref(ref=f"refs/heads/{branch_name}", sha=sha)


def commit_changes(full_name: str, branch_name: str, edits: list[dict], message: str) -> None:
    repository = _github().get_repo(full_name)
    for edit in edits:
        path = edit["file_path"]
        content = edit["new_content"]
        try:
            current = repository.get_contents(path, ref=branch_name)
            repository.update_file(path, message, content, current.sha, branch=branch_name)
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                repository.create_file(path, message, content, branch=branch_name)
            else:
                raise


def create_pull_request(full_name: str, branch_name: str, base_branch: str, title: str, body: str) -> tuple[str, int]:
    pull_request = _github().get_repo(full_name).create_pull(title=title, body=body, head=branch_name, base=base_branch)
    return pull_request.html_url, pull_request.number


def verify_webhook_signature(payload: bytes, signature: str | None) -> bool:
    secret = get_settings().github_webhook_secret
    if not secret or not signature:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def repo_signals(repo_path: str, findings: list[dict]) -> dict:
    root = Path(repo_path)
    def git(args: list[str]) -> str:
        completed = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
        return completed.stdout.strip()
    since = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    commit_count = int(git(["rev-list", "--count", f"--since={since}", "HEAD"]) or 0)
    contributors = len([item for item in git(["shortlog", "-sne", "HEAD"]).splitlines() if item])
    tracked = set(git(["ls-files"]).splitlines())
    gitignore = (root / ".gitignore").read_text(encoding="utf-8") if (root / ".gitignore").exists() else ""
    last_commit = git(["log", "-1", "--format=%ct"])
    days_since = int((datetime.now(timezone.utc).timestamp() - int(last_commit)) / 86400) if last_commit else 0
    return {"commit_count_90d": commit_count, "contributor_count": contributors, "env_file_tracked": any(Path(item).name == ".env" for item in tracked),
        "gitignore_has_env": ".env" in gitignore, "has_precommit_secret_hook": (root / ".pre-commit-config.yaml").exists(),
        "historical_secret_count": sum(item.get("in_history_only", False) for item in findings), "days_since_last_commit": days_since}


def current_commit_sha(repo_path: str) -> str | None:
    completed = subprocess.run(["git", "-C", repo_path, "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return completed.stdout.strip() or None
