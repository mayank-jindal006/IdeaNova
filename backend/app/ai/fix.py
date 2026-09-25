"""AI fix agent: turn one secret finding into a Fix object (see docs/CONTRACTS.md, section 3).

Flow:  check we can fix it -> redact the secret -> ask the LLM to rewrite the file
       -> check the reply -> add .env.example + .gitignore edits in code -> build the Fix.
Whenever something is unsafe or unclear, we return a "flag_only" fix: explanation +
rotation advice, but NO code change. A missing fix is better than a wrong one.
"""
import re

from app.ai.llm import LLMError, complete_json
from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from app.ai.redact import REDACTION_TOKEN, redact

MAX_LINES = 300
ENV_EXAMPLE = ".env.example"
GITIGNORE = ".gitignore"
ENV_VAR_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")

LANGUAGES = {
    ".py": "python",
    ".js": "node", ".mjs": "node", ".cjs": "node",
    ".ts": "node", ".jsx": "node", ".tsx": "node",
}

ROTATION_NOTES = {
    "aws-access-token": "Deactivate this key in AWS IAM (Users -> Security credentials), create a new one, "
                        "and check CloudTrail for any use you don't recognise.",
    "stripe-access-token": "Roll this key in the Stripe Dashboard (Developers -> API keys) and check recent "
                           "payments and API logs for unexpected activity.",
    "github-pat": "Revoke this token in GitHub (Settings -> Developer settings -> Personal access tokens) "
                  "and create a new one with the minimum scopes needed.",
}
DEFAULT_ROTATION_NOTE = "Revoke this credential at its provider and issue a new one."
HISTORY_WARNING = " Removing it from the code does not remove it from git history, so it must be treated as leaked."


def detect_language(file_path: str) -> str | None:
    for ext, language in LANGUAGES.items():
        if file_path.lower().endswith(ext):
            return language
    return None


def rotation_note(finding: dict) -> str:
    return ROTATION_NOTES.get(finding.get("rule_id"), DEFAULT_ROTATION_NOTE) + HISTORY_WARNING


def _fix(finding: dict, explanation: dict, edits: list[dict], tier: str, notes: list[str]) -> dict:
    """Build a Fix object in the exact shape of CONTRACTS.md section 3."""
    is_secret = finding.get("type") == "secret"
    return {
        "finding_id": finding.get("id"),
        "explanation": {
            **explanation,
            "rotation_required": is_secret,
            "rotation_note": rotation_note(finding) if is_secret else "",
        },
        "edits": edits,
        "tier": tier,
        # Filled in by validate.py (Day 3). None = "not checked yet".
        "validation": {"secret_removed": None, "syntax_ok": None, "notes": notes},
    }


def _flag_only(finding: dict, reason: str) -> dict:
    """No code change: explain the finding and tell the user to rotate."""
    explanation = {
        "what": f"{finding.get('title')} in {finding.get('file_path')} (line {finding.get('line')}).",
        "why_dangerous": "Anyone who can read this repository or its history can use this credential.",
        "how_fixed": f"No automatic fix was generated: {reason} Please fix it manually and rotate the credential.",
    }
    return _fix(finding, explanation, edits=[], tier="flag_only", notes=[reason])


def _match_line_endings(new_text: str, original: str) -> str:
    """LLMs return \\n. If the original file uses \\r\\n (Windows), convert back, so only
    the changed lines show up in the diff instead of the whole file."""
    new_text = new_text.replace("\r\n", "\n")
    if "\r\n" in original:
        new_text = new_text.replace("\n", "\r\n")
    newline = "\r\n" if "\r\n" in original else "\n"
    if original.endswith(("\n", "\r\n")) and not new_text.endswith(newline):
        new_text += newline
    return new_text


def _append_line(existing: str, line: str) -> str:
    if existing and not existing.endswith("\n"):
        existing += "\n"
    return existing + line + "\n"


def _support_file_edit(path: str, needed_line: str, match: str,
                       repo_files: list[str], existing_files: dict[str, str], notes: list[str]) -> dict | None:
    """Edit for .env.example or .gitignore: add needed_line unless a line equal to `match` already exists."""
    if path in existing_files:
        original = existing_files[path]
    elif path in repo_files:
        # The file exists but we weren't given its content: overwriting it would destroy it.
        notes.append(f"{path} exists but its content was not provided, so it was not changed.")
        return None
    else:
        original = ""  # new file

    lines = [l.strip() for l in original.splitlines()]
    if match in lines or any(l.startswith(match + "=") for l in lines):
        return None  # already there
    return {"file_path": path, "original_content": original, "new_content": _append_line(original, needed_line)}


def _reply_problem(reply: dict) -> str | None:
    """Return a reason if the LLM reply is unusable, else None."""
    env_var = reply.get("env_var_name")
    content = reply.get("new_content")
    explanation = reply.get("explanation")
    if not isinstance(env_var, str) or not ENV_VAR_PATTERN.match(env_var):
        return "the AI returned an invalid environment variable name."
    if not isinstance(content, str) or not content.strip():
        return "the AI returned an empty file."
    if REDACTION_TOKEN in content:
        return "the AI left the redaction token in the file."
    if not isinstance(explanation, dict) or not all(
            isinstance(explanation.get(k), str) and explanation.get(k) for k in ("what", "why_dangerous", "how_fixed")):
        return "the AI returned an incomplete explanation."
    return None


def generate_fix(finding: dict, file_content: str, repo_files: list[str],
                 existing_files: dict[str, str] | None = None) -> dict:
    """Create a Fix object for one finding.

    finding        -- Finding dict (CONTRACTS.md section 2)
    file_content   -- current content of finding["file_path"] (with the real secret)
    repo_files     -- all file paths in the repo, relative to the repo root
    existing_files -- current content of .env.example / .gitignore if they exist, e.g.
                      {".gitignore": "node_modules\\n"}. Needed so we append instead of overwrite.
    """
    existing_files = existing_files or {}

    if finding.get("type") != "secret":
        return _flag_only(finding, "automatic fixes for this finding type are not supported yet.")
    if finding.get("in_history_only"):
        return _flag_only(finding, "the secret is only in old commits, not in the current code.")

    language = detect_language(finding.get("file_path", ""))
    if language is None:
        return _flag_only(finding, "automatic fixes are only supported for Python and JavaScript/TypeScript files.")
    if len(file_content.splitlines()) > MAX_LINES:
        return _flag_only(finding, f"the file is longer than {MAX_LINES} lines.")

    redacted = redact(file_content, finding)
    if redacted is None:
        # Never send the file if we couldn't hide the secret with certainty.
        return _flag_only(finding, "the secret's exact position could not be confirmed, so the file was not sent to the AI.")

    try:
        reply = complete_json(SYSTEM_PROMPT, build_user_prompt(finding, redacted, language, repo_files))
    except LLMError:
        return _flag_only(finding, "the AI service was not available.")

    problem = _reply_problem(reply)
    if problem:
        return _flag_only(finding, problem)

    env_var = reply["env_var_name"]
    notes: list[str] = []
    edits = [{
        "file_path": finding["file_path"],
        "original_content": file_content,
        "new_content": _match_line_endings(reply["new_content"], file_content),
    }]
    for edit in (
        _support_file_edit(ENV_EXAMPLE, f"{env_var}=", env_var, repo_files, existing_files, notes),
        _support_file_edit(GITIGNORE, ".env", ".env", repo_files, existing_files, notes),
    ):
        if edit:
            edits.append(edit)

    # Tier is decided by tiers.py (Day 4). Until then, everything needs human review.
    return _fix(finding, reply["explanation"], edits, tier="pr_review", notes=notes)