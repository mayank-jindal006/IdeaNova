"""Real end-to-end check of scan -> AI fix -> validation on a GitHub repo, with the REAL LLM.

No database or GitHub token needed: clones a public repo, runs the backend's Gitleaks
scanner, sends every finding through generate_fix(), and prints a summary.
Nothing is pushed anywhere and no secret is sent to the LLM. The fixed files ARE printed,
and they may still contain OTHER secrets from the repo, so only run this on test repos.

Run from the backend folder:
    python -m scripts.try_repo https://github.com/gargrishika2005-cell/repoguard-test-python
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from app.ai.fix import generate_fix
from app.scanners.secrets import scan_secrets


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)   # Windows marks .git files read-only
    func(path)


def main(url: str) -> None:
    tmp = tempfile.mkdtemp(prefix="repoguard-try-")
    try:
        print(f"Cloning {url} ...")
        subprocess.run(["git", "clone", "-q", url, tmp], check=True)
        root = Path(tmp)
        repo_files = [str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*")
                      if p.is_file() and ".git" not in p.parts]
        existing = {name: (root / name).read_text(encoding="utf-8")
                    for name in (".gitignore", ".env.example") if (root / name).is_file()}

        findings = scan_secrets(tmp)
        print(f"Gitleaks found {len(findings)} secret finding(s)\n")
        tiers = Counter()
        live = fixed = 0
        for i, finding in enumerate(findings, 1):
            finding.update(id=i, repo_id=1)
            path = root / finding["file_path"]
            content = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
            start = time.time()
            result = generate_fix(finding, content, repo_files, existing_files=existing)
            tiers[result["tier"]] += 1
            if not finding["in_history_only"]:
                live += 1
                fixed += result["tier"] != "flag_only"

            v = result["validation"]
            print("=" * 72)
            print(f"#{i} {finding['rule_id']} in {finding['file_path']} line {finding['line']}"
                  f"{'  (history only)' if finding['in_history_only'] else ''}")
            print(f"   tier={result['tier']}  secret_removed={v['secret_removed']}  "
                  f"syntax_ok={v['syntax_ok']}  ({time.time() - start:.1f}s)")
            print(f"   how fixed: {result['explanation']['how_fixed']}")
            for note in v["notes"]:
                print(f"   - {note}")
            for edit in result["edits"][:1]:
                print(f"   --- {edit['file_path']} (fixed) ---")
                print("   " + edit["new_content"].replace("\n", "\n   "))
            time.sleep(2)   # stay under free-tier rate limits

        print("=" * 72)
        print(f"SUMMARY: {fixed}/{live} secrets in current code fixed and validated; "
              f"tiers: {dict(tiers)}")
    finally:
        shutil.rmtree(tmp, onerror=_force_remove)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "https://github.com/gargrishika2005-cell/repoguard-test-python")