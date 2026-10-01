"""Offline rehearsal of the WHOLE self-healing loop, on one laptop.

REAL:      Gitleaks scan, the LLM fix (generate_fix), the LLM repair (repair_fix), the agent's
           decisions (agent.py), the database rows (SQLite in memory, our real models),
           and "CI" = actually running the fixed Python code.
SIMULATED: GitHub (branches / PRs / comments are kept in memory and printed), and the
           bad commit that breaks the fix (we delete "import os" on purpose, and say so).

Use it to rehearse, and as the backup demo if the network/webhook fails on demo day.
The fake key is generated randomly at run time, so no secret is ever written to our repo.

Run from the backend folder (needs backend/.env with LLM keys, and Gitleaks on PATH):
    python -m scripts.demo_agent
"""
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models
from app.ai import agent
from app.db.base import Base
from app.scanners.secrets import scan_secrets

MODULE = "app/notify.py"


def fake_github_token() -> str:
    """A random token in GitHub's format. Fake: it was never issued by GitHub."""
    return "ghp_" + "".join(random.choices(string.ascii_letters + string.digits, k=36))


def notify_source(token: str) -> str:
    return (
        '"""Sends build notifications to GitHub."""\n'
        "import json\n"
        "\n"
        f'GITHUB_TOKEN = "{token}"\n'
        'API_URL = "https://api.github.com"\n'
        "\n"
        "\n"
        "def auth_header():\n"
        '    return {"Authorization": f"token {GITHUB_TOKEN}"}\n'
        "\n"
        "\n"
        "def payload(message):\n"
        '    return json.dumps({"body": message})\n'
    )


def step(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


class LocalGitHub:
    """Stands in for Yash's GitHub helpers (CONTRACTS 8.8). Everything stays in memory."""

    def __init__(self, repo_dir: Path):
        self.repo_dir = repo_dir
        self.branches: dict[str, dict[str, str]] = {}
        self.commits = 0

    def _main_files(self) -> dict[str, str]:
        return {str(p.relative_to(self.repo_dir)).replace("\\", "/"): p.read_text(encoding="utf-8")
                for p in self.repo_dir.rglob("*") if p.is_file() and ".git" not in p.parts}

    def _sha(self) -> str:
        self.commits += 1
        return f"local{self.commits:04d}"

    # --- helpers the agent calls ---
    def clone_repo(self, full_name):
        return str(self.repo_dir)

    def cleanup_clone(self, path):
        pass

    def open_fix_pr(self, db, fix_id):
        fix = db.get(models.Fix, fix_id)
        branch = f"repoguard/fix-{fix.finding_id}"
        self.branches[branch] = self._main_files()
        for edit in fix.edits:
            self.branches[branch][edit["file_path"]] = edit["new_content"]
        fix.branch, fix.pr_url, fix.pr_number, fix.head_sha = branch, "local-pr-1", 1, self._sha()
        db.commit()
        print(f"  [GitHub] opened PR #1 from {branch} ({len(fix.edits)} file(s) changed)")
        return fix

    def push_fix_commit(self, full_name, branch, edits, message):
        for edit in edits:
            self.branches[branch][edit["file_path"]] = edit["new_content"]
        sha = self._sha()
        print(f"  [GitHub] pushed {sha} to {branch}: {message}")
        return sha

    def get_branch_files(self, full_name, branch, paths):
        return {p: self.branches[branch].get(p) for p in paths}

    def comment_on_pr(self, full_name, pr_number, body):
        print(f"  [GitHub] comment on PR #{pr_number}:\n    " + body.replace("\n", "\n    "))


def run_ci(files: dict[str, str]) -> tuple[str, str]:
    """'CI' = really import the module and call its functions in a clean Python process.
    No env vars are set, exactly like a CI runner without secrets."""
    with tempfile.TemporaryDirectory(prefix="repoguard-ci-") as tmp:
        for path, content in files.items():
            target = Path(tmp) / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        (Path(tmp) / "app" / "__init__.py").touch()
        test = "import app.notify as n; n.auth_header(); n.payload('hi'); print('1 passed')"
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        done = subprocess.run([sys.executable, "-c", test], cwd=tmp, capture_output=True, text=True,
                              timeout=60, env=env)
    log = (done.stdout + done.stderr).strip()
    return ("success" if done.returncode == 0 else "failure"), log


def timeline(db) -> None:
    for run in db.query(models.AgentRun).order_by(models.AgentRun.id):
        print(f"  {run.step:<14} {run.detail or ''}"[:150])


def main() -> None:
    if not shutil.which(os.getenv("GITLEAKS_BIN", "gitleaks")):
        sys.exit("Gitleaks not found on PATH. Windows: $env:PATH = \"C:\\tools;\" + $env:PATH")

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    repo = models.Repo(full_name="demo/test-repo", default_branch="main", auto_fix_enabled=True)
    db.add(repo)
    db.commit()

    work = Path(tempfile.mkdtemp(prefix="repoguard-demo-"))
    try:
        step("1. Developer pushes a file with a hardcoded GitHub token (fake, random)")
        (work / "app").mkdir()
        (work / MODULE).write_text(notify_source(fake_github_token()), encoding="utf-8")
        (work / "app" / "__init__.py").write_text("", encoding="utf-8")
        print(f"  {MODULE} line 4: GITHUB_TOKEN = \"ghp_****\"")

        step("2. Push webhook -> Gitleaks scan (real)")
        found = scan_secrets(str(work), include_history=False)
        if not found:
            sys.exit("  Gitleaks found nothing -- check the Gitleaks install.")
        scan = models.Scan(repo_id=repo.id, trigger=models.ScanTrigger.push, status=models.ScanStatus.done)
        db.add(scan)
        db.flush()
        ids = []
        for item in found:
            finding = models.Finding(scan_id=scan.id, repo_id=repo.id, **item)
            db.add(finding)
            db.flush()
            ids.append(finding.id)
            print(f"  found {item['rule_id']} in {item['file_path']} line {item['line']} ({item['secret_masked']})")
        db.commit()

        github = LocalGitHub(work)
        agent._github = lambda: github   # GitHub is the only simulated part

        step("3. Agent: generate fix (real LLM) -> validate -> open PR")
        agent.handle_new_findings(db, repo.id, ids)
        fix = db.query(models.Fix).first()
        if fix is None or not fix.branch:
            timeline(db)
            sys.exit("\n  No PR was opened (see the timeline above). Stopping.")
        print(f"  tier={getattr(fix.tier, 'value', fix.tier)}  ci_status={fix.ci_status}")

        step("4. CI runs on the fix PR (real Python, no env vars set)")
        conclusion, log = run_ci(github.branches[fix.branch])
        print(f"  CI: {conclusion}  |  {log.splitlines()[-1] if log else ''}")
        agent.handle_ci_result(db, fix.id, conclusion, log)

        step("5. SIMULATED bad commit on the fix branch: 'import os' deleted on purpose")
        files = github.branches[fix.branch]
        broken = "".join(l for l in files[MODULE].splitlines(keepends=True) if l.strip() != "import os")
        if broken == files[MODULE]:
            print("  (the fix has no separate 'import os' line, so there is nothing to break; skipping)")
        else:
            github.push_fix_commit(repo.full_name, fix.branch, [{"file_path": MODULE, "new_content": broken}],
                                   "simulate a broken fix (demo only)")
            conclusion, log = run_ci(files)
            print(f"  CI: {conclusion}  |  {log.splitlines()[-1] if log else ''}")

            step("6. Agent reads the CI log -> repairs (real LLM) -> pushes")
            agent.handle_ci_result(db, fix.id, conclusion, log)

            step("7. CI runs again on the repaired branch")
            conclusion, log = run_ci(github.branches[fix.branch])
            print(f"  CI: {conclusion}  |  {log.splitlines()[-1] if log else ''}")
            agent.handle_ci_result(db, fix.id, conclusion, log)

        step("Agent timeline (agent_runs table)")
        timeline(db)
        db.refresh(fix)
        print(f"\nFinal: ci_status={fix.ci_status}, repair_attempts={fix.repair_attempts}. "
              "Nothing was merged: a human reviews the PR.")
        print(f"\n--- {MODULE} on {fix.branch} ---\n{github.branches[fix.branch][MODULE]}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        db.close()


if __name__ == "__main__":
    main()
