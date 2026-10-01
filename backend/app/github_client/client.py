import hashlib
import hmac
import io
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
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


def clone_repo_ref(full_name: str, ref: str) -> str:
    """Clone a repository and check out an immutable commit SHA for PR scanning."""
    destination = clone_repo(full_name)
    completed = subprocess.run(["git", "-C", destination, "checkout", "--detach", ref], capture_output=True, text=True, check=False, timeout=60)
    if completed.returncode:
        cleanup_clone(destination)
        raise RuntimeError(completed.stderr.strip() or f"Could not check out {ref}")
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


def push_fix_commit(full_name, branch, edits, message):
    """Push a follow-up set of full-file edits to an existing fix branch."""
    commit_changes(full_name, branch, edits, message)


def get_branch_files(full_name, branch, paths):
    repository = _github().get_repo(full_name)
    files = {}
    for path in paths:
        try:
            contents = repository.get_contents(path, ref=branch)
            files[path] = contents.decoded_content.decode("utf-8")
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                files[path] = None
            else:
                raise
    return files


def get_failed_job_log(full_name, run_id, max_lines=200):
    """Download a workflow run's ZIP log archive and return its trailing lines."""
    token = get_settings().github_token
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not configured")
    url = f"https://api.github.com/repos/{full_name}/actions/runs/{run_id}/logs"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        archive = response.read()
    lines = []
    with zipfile.ZipFile(io.BytesIO(archive)) as logs:
        for name in logs.namelist():
            if name.endswith(".txt"):
                lines.extend(logs.read(name).decode("utf-8", errors="replace").splitlines())
    return "\n".join(lines[-max_lines:])


def comment_on_pr(full_name, pr_number, body):
    _github().get_repo(full_name).get_pull(pr_number).create_issue_comment(body)


def set_commit_status(full_name, sha, state, description, context="RepoGuard"):
    _github().get_repo(full_name).get_commit(sha).create_status(state=state, description=description, context=context)


def open_fix_pr(db, fix_id):
    """Create a branch, push the generated edits, and open a reviewable pull request."""
    from app.models import FindingStatus, Fix, FixStatus

    fix = db.get(Fix, fix_id)
    if not fix:
        raise ValueError("FIX_NOT_FOUND")
    if fix.tier.value == "flag_only" or not fix.edits:
        raise ValueError("FIX_NOT_APPLICABLE")
    finding, repo = fix.finding, fix.finding.repo
    branch = fix.branch or f"repoguard/fix-{finding.id}"
    try:
        create_branch(repo.full_name, branch, repo.default_branch)
    except Exception as exc:
        if getattr(exc, "status", None) != 422:
            raise
    push_fix_commit(repo.full_name, branch, fix.edits, f"RepoGuard: fix {finding.title}")
    url, number = create_pull_request(repo.full_name, branch, repo.default_branch, f"RepoGuard: {finding.title}", _fix_pr_body(finding, fix))
    fix.branch, fix.pr_url, fix.pr_number = branch, url, number
    fix.status, finding.status = FixStatus.pr_opened, FindingStatus.pr_opened
    return {"pr_url": url, "pr_number": number}


def _fix_pr_body(finding, fix) -> str:
    explanation = fix.explanation
    return f"""## 🔐 RepoGuard: {finding.title}
**Severity:** {finding.severity.value} · **Rule:** {finding.rule_id}

### What this PR changes
{explanation.get('how_fixed', '')}

### ⚠️ Rotation required
{explanation.get('rotation_note', '')}

_Generated by RepoGuard. Review before merging. Nothing is merged automatically._"""


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
