from __future__ import annotations

import hashlib
import hmac
import os
import re
from base64 import b64encode
import shutil
import subprocess
import tempfile
from pathlib import Path
from pathlib import PurePosixPath

from github import Github

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
    """Return one Git child-process environment with non-persistent auth.

    Git for Windows executes custom credential helpers through its MSYS shell.
    Some locked-down Windows environments prohibit that shell from creating its
    named object, so a helper can fail before Git contacts GitHub.  A scoped
    ``http.*.extraheader`` is handled directly by Git and has the same lifetime
    as this child process.  It is not written to repository or global config.
    """
    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith("GIT_TRACE") or key in {"GIT_CURL_VERBOSE", "GIT_CONFIG_PARAMETERS"}:
            environment.pop(key)
    environment.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_1": "AUTHORIZATION: basic " + b64encode(
            f"x-access-token:{token}".encode("utf-8")
        ).decode("ascii"),
    })
    return environment


def _run_git(command: list[str], environment: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, capture_output=True, text=True, env=environment)


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


def create_branch(full_name: str, branch: str, base_branch: str, *, base_sha: str | None = None) -> None:
    repo = _github().get_repo(full_name)
    source = repo.get_branch(base_branch)
    if base_sha is not None and source.commit.sha != base_sha:
        raise ValueError("Base branch changed after validation")
    target_sha = base_sha or source.commit.sha
    if not _GIT_COMMIT_SHA.fullmatch(target_sha):
        raise ValueError("Base commit is invalid")
    repo.create_git_ref(ref=f"refs/heads/{branch}", sha=target_sha)


def commit_file_changes(full_name: str, branch: str, edits: list[dict]) -> None:
    repo = _github().get_repo(full_name)
    for edit in edits:
        path, content = edit["file_path"], edit["new_content"]
        if (
            not isinstance(path, str)
            or "\\" in path
            or path.startswith("/")
            or ":" in path
            or not PurePosixPath(path).parts
            or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
            or not isinstance(content, str)
        ):
            raise ValueError("Remediation edit is invalid")
        try:
            existing = repo.get_contents(path, ref=branch)
            repo.update_file(path, "RepoGuard approved remediation", content, existing.sha, branch=branch)
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                raise ValueError("Remediation target no longer exists") from None
            raise


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
