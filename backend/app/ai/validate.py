"""Check an AI-generated fix BEFORE anyone sees it.

We never trust the LLM's claim that a fix works. Two independent checks:
  1. secret_removed -- write the edited files to a temporary folder and scan them
                       with Gitleaks. The fixed file must have zero leaks.
  2. syntax_ok      -- the fixed file must still be valid code
                       (Python: compile(); JavaScript: node --check).

Result shape (CONTRACTS.md section 3, "validation"):
  {"secret_removed": bool | None, "syntax_ok": bool | None, "notes": [str, ...]}
None means "could not be checked" (e.g. Gitleaks or Node not installed) and is
never reported as a pass.
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

GITLEAKS_TIMEOUT = 60
NODE_TIMEOUT = 30

PYTHON_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs")


def _gitleaks_bin() -> str | None:
    return shutil.which(os.getenv("GITLEAKS_BIN", "gitleaks"))


def _write_edits(folder: Path, edits: list[dict]) -> None:
    for edit in edits:
        target = (folder / edit["file_path"]).resolve()
        if folder.resolve() not in target.parents:
            raise ValueError(f"Unsafe file path in fix: {edit['file_path']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        # newline="" keeps \r\n exactly as the fix has it
        target.write_text(edit["new_content"], encoding="utf-8", newline="")


def find_secrets(file_path: str, content: str) -> list[str] | None:
    """All secret values Gitleaks finds in one file (used to hide them from the LLM).
    None if Gitleaks is unavailable or fails, in which case the caller must NOT send the file."""
    gitleaks = _gitleaks_bin()
    if gitleaks is None:
        return None
    with tempfile.TemporaryDirectory(prefix="repoguard-find-") as tmp:
        folder = Path(tmp) / "files"
        folder.mkdir()
        report = Path(tmp) / "report.json"   # deleted with the temp folder
        try:
            _write_edits(folder, [{"file_path": file_path, "new_content": content}])
            completed = subprocess.run(
                [gitleaks, "dir", str(folder), "--report-format", "json",
                 "--report-path", str(report), "--no-banner"],
                capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT, check=False,
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
        if completed.returncode not in (0, 1):
            return None
        leaks = json.loads(report.read_text(encoding="utf-8") or "[]") if report.exists() else []
    return [leak["Secret"] for leak in leaks if leak.get("Secret")]


def check_secret_removed(edits: list[dict], main_file: str, secret: str | None = None) -> tuple[bool | None, str]:
    """Is the finding's secret gone from the fixed file?

    With `secret` (the normal case): True if that exact value no longer appears anywhere in the
    fix AND Gitleaks no longer reports it. Other secrets in the same file are separate findings;
    they are mentioned in the note but don't fail this fix.
    Without `secret`: True only if Gitleaks finds no secret at all in the main file.
    The secret value itself never appears in the returned note.
    """
    if secret and any(secret in edit["new_content"] for edit in edits):
        return False, f"The original secret value is still present in the fix for {main_file}."

    gitleaks = _gitleaks_bin()
    if gitleaks is None:
        return None, "Gitleaks is not installed, so the secret removal could not be checked."

    with tempfile.TemporaryDirectory(prefix="repoguard-validate-") as tmp:
        folder = Path(tmp) / "files"
        folder.mkdir()
        report = Path(tmp) / "report.json"   # deleted with the temp folder
        _write_edits(folder, edits)
        completed = subprocess.run(
            [gitleaks, "dir", str(folder), "--report-format", "json",
             "--report-path", str(report), "--no-banner"],
            capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT, check=False,
        )
        # Gitleaks exit codes: 0 = no leaks, 1 = leaks found, anything else = real error
        if completed.returncode not in (0, 1):
            return None, "Gitleaks failed to run on the fixed file."
        leaks = json.loads(report.read_text(encoding="utf-8") or "[]") if report.exists() else []

    main = main_file.replace("\\", "/")
    in_main = [leak for leak in leaks if leak.get("File", "").replace("\\", "/").endswith(main)]
    if secret is None:
        if in_main:
            rules = ", ".join(sorted({leak.get("RuleID", "?") for leak in in_main}))
            return False, f"Gitleaks still finds a secret in {main_file} ({rules})."
        return True, "Re-scanned the fixed file with Gitleaks: no secrets found."

    same = [leak for leak in in_main if leak.get("Secret") == secret or secret in leak.get("Match", "")]
    if same:
        return False, f"Gitleaks still finds this secret in {main_file}."
    others = [leak for leak in in_main if leak not in same]
    if others:
        rules = ", ".join(sorted({leak.get("RuleID", "?") for leak in others}))
        return True, (f"Re-scanned with Gitleaks: this secret is gone. {len(others)} other secret(s) remain "
                      f"in {main_file} ({rules}); they are separate findings.")
    return True, "Re-scanned the fixed file with Gitleaks: no secrets found."


def check_syntax(file_path: str, content: str) -> tuple[bool | None, str]:
    """Python via compile(), JavaScript via `node --check`."""
    lower = file_path.lower()
    if lower.endswith(PYTHON_EXT):
        try:
            compile(content, file_path, "exec")
        except SyntaxError as exc:
            return False, f"Python syntax error on line {exc.lineno}: {exc.msg}."
        return True, "Python syntax check passed."

    if lower.endswith(JS_EXT):
        node = shutil.which("node")
        if node is None:
            return None, "Node.js is not installed, so the JavaScript syntax could not be checked."
        with tempfile.TemporaryDirectory(prefix="repoguard-syntax-") as tmp:
            path = Path(tmp) / Path(file_path).name
            path.write_text(content, encoding="utf-8", newline="")
            completed = subprocess.run([node, "--check", str(path)], capture_output=True,
                                       text=True, timeout=NODE_TIMEOUT, check=False)
        if completed.returncode != 0:
            error = next((l for l in completed.stderr.splitlines() if "Error" in l), completed.stderr.strip())
            return False, f"JavaScript syntax error: {error[:200]}"
        return True, "JavaScript syntax check passed."

    return None, f"No syntax checker for {file_path}."


def validate_fix(edits: list[dict], main_file: str, secret: str | None = None) -> dict:
    """Run both checks on a fix. `main_file` is the file that contained the secret;
    `secret` is its exact value (used only for comparison, never returned)."""
    notes: list[str] = []
    main_edit = next((e for e in edits if e["file_path"] == main_file), None)
    if main_edit is None:
        return {"secret_removed": False, "syntax_ok": None, "notes": ["The fix does not change the affected file."]}

    try:
        secret_removed, note = check_secret_removed(edits, main_file, secret)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        secret_removed, note = None, f"Secret check could not run: {exc}"
    notes.append(note)

    try:
        syntax_ok, note = check_syntax(main_file, main_edit["new_content"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        syntax_ok, note = None, f"Syntax check could not run: {exc}"
    notes.append(note)

    return {"secret_removed": secret_removed, "syntax_ok": syntax_ok, "notes": notes}


def passed(validation: dict) -> bool:
    return validation.get("secret_removed") is True and validation.get("syntax_ok") is True