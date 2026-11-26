from __future__ import annotations

import hashlib
import hmac
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from github import Github

from app.core.process_env import subprocess_environment
from app.core.scan_paths import require_scan_root, validate_scan_path
from app.settings import settings

_GITHUB_FULL_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]+$")
_GIT_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def is_valid_github_full_name(full_name: object) -> bool:
    return isinstance(full_name, str) and _GITHUB_FULL_NAME.fullmatch(full_name) is not None


def is_valid_github_push_ref(ref: object) -> bool:
    if not isinstance(ref, str) or not ref.startswith("refs/heads/"):
        return False
    branch = ref.removeprefix("refs/heads/")
    if not branch or branch.startswith("-") or branch.endswith("/") or "//" in branch or ".." in branch or "@{" in branch or branch.endswith("."):
        return False
    forbidden = set(" ~^:?*[\\")
    components = branch.split("/")
    return not any(character in forbidden or ord(character) < 32 or ord(character) == 127 for character in branch) and all(
        component and not component.startswith(".") and not component.lower().endswith(".lock")
        for component in components
    )


def _git_auth_environment(token: str) -> dict[str, str]:
    environment = subprocess_environment(include_proxy=True)
    environment.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "credential.helper",
        "GIT_CONFIG_VALUE_1": (
            '!f() { if [ "$1" = get ]; then '
            'printf "username=x-access-token\\npassword=%s\\n\\n" "$REPOGUARD_GIT_TOKEN"; '
            "fi; }; f"
        ),
        "REPOGUARD_GIT_TOKEN": token,
    })
    return environment


def _run_git(command: list[str], environment: dict[str, str] | None = None) -> None:
    subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=environment if environment is not None else subprocess_environment(),
    )


def _github() -> Github:
    if not settings.github_token:
        raise RuntimeError("GITHUB_TOKEN is not configured")
    return Github(settings.github_token)


def default_branch(full_name: str) -> str:
    return _github().get_repo(full_name).default_branch


def clone_repo(full_name: str, commit_sha: str | None = None, ref: str | None = None) -> str:
    """Clone a repository without persisting credentials, optionally at a pushed commit."""
    if not is_valid_github_full_name(full_name):
        raise ValueError("Repository name is invalid")
    if (commit_sha is None) != (ref is None):
        raise ValueError("A pushed commit and ref must be provided together")
    if commit_sha is not None and (not _GIT_COMMIT_SHA.fullmatch(commit_sha) or not is_valid_github_push_ref(ref)):
        raise ValueError("Pushed commit or ref is invalid")
    if not settings.github_token:
        raise RuntimeError("GITHUB_TOKEN is not configured")

    root = require_scan_root()
    target = Path(tempfile.mkdtemp(prefix="repoguard-", dir=root))
    url = f"https://github.com/{full_name}.git"
    environment = _git_auth_environment(settings.github_token)
    try:
        clone_command = ["git", "clone"]
        if commit_sha is not None:
            clone_command.append("--no-checkout")
        _run_git([*clone_command, url, str(target)], environment)
        if commit_sha is not None and ref is not None:
            fetched_ref = "refs/repoguard/push"
            _run_git(
                ["git", "-C", str(target), "fetch", "--no-tags", "origin", f"+{ref}:{fetched_ref}"],
                environment,
            )
            _run_git(["git", "-C", str(target), "merge-base", "--is-ancestor", commit_sha, fetched_ref])
            _run_git(["git", "-C", str(target), "checkout", "--detach", commit_sha])
        return str(validate_scan_path(target))
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError("Repository checkout failed") from None


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
    environment = subprocess_environment()
    commits = subprocess.run(["git", "-C", repo_path, "rev-list", "--count", "--since=90.days", "HEAD"], capture_output=True, text=True, check=False, env=environment).stdout.strip()
    contributors = subprocess.run(["git", "-C", repo_path, "shortlog", "-sne", "HEAD"], capture_output=True, text=True, check=False, env=environment).stdout.splitlines()
    last_commit = subprocess.run(["git", "-C", repo_path, "log", "-1", "--format=%ct"], capture_output=True, text=True, check=False, env=environment).stdout.strip()
    import time
    tracked_env = subprocess.run(
        ["git", "-C", repo_path, "ls-files", ".env"],
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()
    return {"commit_count_90d": int(commits or 0), "contributor_count": len(contributors), "env_file_tracked": bool(tracked_env), "gitignore_has_env": ".env" in gitignore, "has_precommit_secret_hook": (root / ".git" / "hooks" / "pre-commit").exists(), "historical_secret_count": 0, "days_since_last_commit": int((time.time() - int(last_commit)) / 86400) if last_commit else 0}
