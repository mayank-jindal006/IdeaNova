"""Self-healing agent (docs/CONTRACTS.md, section 8).

Part 1: two pure helpers -- no database, no GitHub, fully unit-tested.
  extract_ci_errors(log_text)  -> the useful error lines from a failed CI log
  repair_fix(finding, files, ci_errors, repo_files) -> a Fix that repairs a fix which broke CI

Part 2: the agent loop, called by the backend (webhooks):
  handle_new_findings(db, repo_id, finding_ids) -> new secret on push: fix -> PR
  handle_ci_result(db, fix_id, conclusion, log_text) -> CI finished on a fix PR: done / repair / give up
It uses Yash's helpers from CONTRACTS 8.8 (open_fix_pr, push_fix_commit, get_branch_files,
comment_on_pr, record_agent_run). They are looked up when called, so this file imports fine
before they exist; the tests replace them with fakes.

Safety rules (section 8.4) enforced here:
  * every secret in the file AND in the CI log is hidden before anything is sent to the LLM
  * a repair only changes the affected file; it is always tier pr_review (a human merges)
  * a repair that adds a secret, breaks syntax or rewrites too much is rejected (flag_only)
"""
import inspect
import logging
import re
from pathlib import Path

from app.ai.fix import MAX_LINES, _flag_only, _fix, _match_line_endings, _retry_prompt, detect_language
from app.ai.llm import LLMError, complete_json
from app.ai.prompts import LOG_REDACTION_TOKEN, REPAIR_SYSTEM_PROMPT, build_repair_prompt
from app.ai.redact import hide_other_secrets, restore_other_secrets
from app.ai.tiers import changed_lines
from app.ai.validate import check_syntax, find_secrets

MAX_REPAIR_ATTEMPTS = 2        # repairs per fix (contract 8.4)
MAX_AUTO_FIXES_PER_PUSH = 5    # never flood a repo with PRs from one push
MAX_LLM_ATTEMPTS = 2           # inside one repair: first try + one retry with the problem
MAX_LOG_LINES = 200            # contract 8.4: at most the last 200 log lines are used
MAX_LINE_LENGTH = 300
MAX_REPAIR_CHANGED_LINES = 10  # a repair is a small correction, not a rewrite

# ---------------------------------------------------------------------------
# extract_ci_errors
# ---------------------------------------------------------------------------

_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z ?")   # GitHub Actions prefix
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")                                  # terminal colours
_ERROR_LINE = re.compile(
    r"Traceback \(most recent call last\)"
    r"|^\s*File \".+\", line \d+"            # Python traceback frame
    r"|\b\w*(Error|Exception)\b"             # NameError: ..., KeyError: ..., SyntaxError, ...
    r"|^E\s+"                                # pytest failure detail lines
    r"|^>\s{3,}\S"                           # pytest: the failing source line (">       x = 1")
    r"|^(FAILED|ERROR)\b"                    # pytest summary
    r"|^=+ .*(failed|error).* =+$"           # pytest "==== 1 failed in 0.1s ===="
    r"|npm ERR!"
    r"|##\[error\]"
    r"|^\s+at .+:\d+:\d+\)?$"                # Node stack frame
    r"|[\w./-]+\.(py|js|mjs|cjs|ts):\d+",    # file.py:12 references
    re.IGNORECASE,
)
_PY_FRAME = re.compile(r'^\s*File ".+", line \d+')


def _clean(line: str) -> str:
    return _ANSI.sub("", _TIMESTAMP.sub("", line)).rstrip()


def extract_ci_errors(log_text: str, max_lines: int = 40) -> list[str]:
    """Return the error-relevant lines of a CI log, oldest first, at most max_lines.

    Only the last MAX_LOG_LINES lines of the log are looked at. Timestamps and colour codes
    are removed, long lines are cut, and repeated lines are kept once.
    NOTE: the result can still contain secrets (e.g. a traceback quoting a source line);
    repair_fix() hides them before anything goes to the LLM.
    """
    lines = [_clean(l) for l in (log_text or "").splitlines()[-MAX_LOG_LINES:]]
    keep: list[str] = []
    seen: set[str] = set()
    for i, line in enumerate(lines):
        # The line right after a Python traceback frame is the source code that failed.
        after_frame = i > 0 and _PY_FRAME.match(lines[i - 1]) is not None
        if not line.strip() or not (after_frame or _ERROR_LINE.search(line)):
            continue
        line = line[:MAX_LINE_LENGTH]
        if line in seen:
            continue
        seen.add(line)
        keep.append(line)
    return keep[-max_lines:] if max_lines > 0 else []


# ---------------------------------------------------------------------------
# repair_fix
# ---------------------------------------------------------------------------

_ENV_READ = re.compile(r"os\.getenv\(|os\.environ|process\.env")


def _masked_pattern(finding: dict) -> re.Pattern | None:
    """Matches the ORIGINAL secret (we only know its first and last 4 characters)."""
    masked = finding.get("secret_masked") or ""
    if len(masked) < 8 or "****" not in masked:
        return None
    return re.compile(re.escape(masked[:4]) + r"[^\s\"'`]{0,200}?" + re.escape(masked[-4:]))


def _hide_in_log(ci_errors: list[str], values: list[str], pattern: re.Pattern | None) -> list[str] | None:
    """Hide secrets in the CI error lines. None if Gitleaks can't check the log."""
    found = find_secrets("ci-log.txt", "\n".join(ci_errors) + "\n")
    if found is None:
        return None
    hidden = []
    for line in ci_errors:
        for value in sorted(set(values) | set(found), key=len, reverse=True):
            if value:
                line = line.replace(value, LOG_REDACTION_TOKEN)
        if pattern:
            line = pattern.sub(LOG_REDACTION_TOKEN, line)
        hidden.append(line)
    return hidden


def _repair_problem(reply: dict, sent: str, others: dict[str, str]) -> str | None:
    content = reply.get("new_content")
    if not isinstance(content, str) or not content.strip():
        return "the AI returned an empty file."
    if not isinstance(reply.get("cause"), str) or not isinstance(reply.get("how_fixed"), str):
        return "the AI did not explain the repair."
    if LOG_REDACTION_TOKEN in content or "<<REDACTED_SECRET>>" in content:
        return "the AI copied a redaction token into the file."
    for placeholder in others:
        if content.count(placeholder) != sent.count(placeholder):
            return f"the AI changed {placeholder}, which belongs to a different finding."
    if _ENV_READ.search(sent) and not _ENV_READ.search(content):
        return "the AI removed the environment variable read; the secret must stay out of the code."
    return None


def _check_repair(finding: dict, before: str, after: str, known: list[str],
                  pattern: re.Pattern | None) -> dict:
    """Validation for a repair: no secret came back or was added, syntax OK, change is small."""
    notes: list[str] = []
    no_secret: bool | None = True
    now = find_secrets(finding["file_path"], after)
    if now is None:
        no_secret = None
        notes.append("Gitleaks is not available, so the repair could not be checked for secrets.")
    elif [v for v in now if v not in known] or (pattern and pattern.search(after)):
        no_secret = False
        notes.append("The repair adds a secret to the file.")
    else:
        notes.append("Re-scanned the repaired file with Gitleaks: no new secret.")

    syntax_ok, note = check_syntax(finding["file_path"], after)
    notes.append(note)

    size = changed_lines(before, after)
    small = size <= MAX_REPAIR_CHANGED_LINES
    if not small:
        notes.append(f"The repair changes {size} lines (limit {MAX_REPAIR_CHANGED_LINES}); too large to trust.")
    return {"secret_removed": no_secret, "syntax_ok": syntax_ok, "notes": notes, "small": small}


def _passed(check: dict) -> bool:
    return check["secret_removed"] is True and check["syntax_ok"] is True and check["small"]


def repair_fix(finding: dict, files: dict[str, str], ci_errors: list[str], repo_files: list[str]) -> dict:
    """Repair a fix whose PR failed the repository's CI.

    finding    -- the original secret Finding (CONTRACTS section 2)
    files      -- current content on the fix branch, at least {finding["file_path"]: "..."}
    ci_errors  -- output of extract_ci_errors() (may still contain secrets; hidden here)
    repo_files -- all file paths in the repo (kept for the same signature as generate_fix)

    Returns a Fix (same shape as generate_fix). tier is "pr_review" when the repair passed our
    checks, "flag_only" (no edits) when it is impossible or unsafe. Whether it really fixes CI
    is only known when CI runs again on the pushed commit.
    """
    path = finding.get("file_path", "")
    if finding.get("type") != "secret":
        return _flag_only(finding, "only secret fixes are repaired automatically.")
    if path not in files:
        return _flag_only(finding, "the affected file was not found on the fix branch.")
    language = detect_language(path)
    if language is None:
        return _flag_only(finding, "automatic repairs are only supported for Python and JavaScript files.")
    if not ci_errors:
        return _flag_only(finding, "no error lines were found in the CI log, so there is nothing to repair.")

    before = files[path]
    if len(before.splitlines()) > MAX_LINES:
        return _flag_only(finding, f"the file is longer than {MAX_LINES} lines.")

    pattern = _masked_pattern(finding)
    if pattern and pattern.search(before):
        return _flag_only(finding, "the original secret is back in the file on the fix branch; a human must check it.")

    # Hide every secret Gitleaks finds in the file, and every secret in the log.
    known = find_secrets(path, before)
    if known is None:
        return _flag_only(finding, "Gitleaks is not available to check the file, so it was not sent to the AI.")
    sent, others = hide_other_secrets(before, known)
    errors = _hide_in_log(ci_errors, known, pattern)
    if errors is None:
        return _flag_only(finding, "Gitleaks is not available to check the CI log, so it was not sent to the AI.")

    prompt = build_repair_prompt(finding, sent, language, errors)
    check: dict = {}
    for attempt in range(1, MAX_LLM_ATTEMPTS + 1):
        try:
            reply = complete_json(REPAIR_SYSTEM_PROMPT, prompt)
        except LLMError:
            return _flag_only(finding, "the AI service was not available.")

        if reply.get("fixable") is False:
            cause = reply.get("cause") if isinstance(reply.get("cause"), str) else "unknown cause"
            return _flag_only(finding, f"the CI failure does not seem to be caused by this fix ({cause[:200]}).")

        problem = _repair_problem(reply, sent, others)
        if problem:
            if attempt < MAX_LLM_ATTEMPTS:
                prompt = _retry_prompt(prompt, [problem])
                continue
            return _flag_only(finding, problem)

        after = _match_line_endings(restore_other_secrets(reply["new_content"], others), before)
        if after == before:
            problem_notes = ["the AI returned the file unchanged."]
        else:
            check = _check_repair(finding, before, after, known, pattern)
            if _passed(check):
                break
            problem_notes = check["notes"]
        if attempt < MAX_LLM_ATTEMPTS:
            prompt = _retry_prompt(prompt, problem_notes)
    else:
        result = _flag_only(finding, "the AI repair did not pass validation.")
        result["validation"]["notes"] = check.get("notes", []) + result["validation"]["notes"]
        return result

    explanation = {
        "what": f"CI failed after the security fix in {path}: {reply['cause']}",
        "why_dangerous": "A fix that breaks the build cannot be merged, so the secret would stay in the code.",
        "how_fixed": reply["how_fixed"],
    }
    edit = {"file_path": path, "original_content": before, "new_content": after}
    notes = ["Repair of a fix that failed CI. CI must pass again before a human merges it."]
    if attempt > 1:
        notes.append("The first repair attempt was rejected; this is the corrected second attempt.")
    return _fix(finding, explanation, [edit], tier="pr_review", notes=notes, validation=check)


# ---------------------------------------------------------------------------
# Part 2: the agent loop (database + GitHub)
# ---------------------------------------------------------------------------

logger = logging.getLogger("repoguard.agent")
_FAILED_STEPS = {"ci_failed", "repair_failed", "gave_up", "error"}
BRANCH_PREFIX = "repoguard/fix-"
SUPPORT_FILES = (".gitignore", ".env.example")
NEEDS_HUMAN = ("RepoGuard could not make CI pass on this fix automatically, so it stopped trying. "
               "**Needs human review.** The secret is still in the code on the default branch: "
               "rotate it and finish this fix by hand.")


def _github():
    """Yash's GitHub helpers (CONTRACTS 8.8). Imported on use so this module loads without them."""
    from app.github_client import client
    return client


def _log(db, repo_id: int, step: str, detail: str, finding_id: int | None = None,
         fix_id: int | None = None, attempt: int = 0) -> None:
    """One row in agent_runs (Yash's record_agent_run). `detail` must NEVER contain a secret."""
    try:
        from app.agent_log import record_agent_run
    except ImportError:   # table not there yet: still leave a trace in the server log
        logger.info("agent %s repo=%s finding=%s fix=%s attempt=%s: %s",
                    step, repo_id, finding_id, fix_id, attempt, detail)
        return
    params = inspect.signature(record_agent_run).parameters
    kwargs = {"step": step, "detail": detail, "finding_id": finding_id, "fix_id": fix_id}
    if "attempt" in params:
        kwargs["attempt"] = attempt
    if "status" in params:
        kwargs["status"] = "failed" if step in _FAILED_STEPS else "ok"
    record_agent_run(db, repo_id, **kwargs)   # keywords only: works whatever the argument order is
    db.commit()   # record_agent_run only adds the row; commit so a later rollback can't lose it


def _models():
    from app import models
    return models


def _finding_dict(finding) -> dict:
    from app.schemas import FindingOut
    return FindingOut.model_validate(finding).model_dump(mode="json")


def _ci(status: str) -> str:
    """fixes.ci_status is stored as text: "none" | "pending" | "passed" | "failed"."""
    return status


def _value(x):
    """Enum -> its value; plain strings stay as they are."""
    return getattr(x, "value", x)


def _error_summary(ci_errors: list[str]) -> str:
    """Short, secret-free summary for agent_runs.detail, e.g. "NameError: name 'os' is not defined"."""
    matches = [m for m in (re.search(r"\b(\w+(?:Error|Exception))\b(:.*)?", l) for l in reversed(ci_errors)) if m]
    if matches:
        # prefer "NameError: name 'os' is not defined" over a bare "app/config.py:5: NameError"
        best = sorted(matches, key=lambda m: m.group(2) is None)[0]
        text = (best.group(1) + (best.group(2) or ""))[:150]
        return text if find_secrets("detail.txt", text + "\n") == [] else best.group(1)   # unsure -> name only
    return f"{len(ci_errors)} error line(s) in the CI log" if ci_errors else "no error lines in the CI log"


def _read_repo(clone_path: str, finding_path: str) -> tuple[str, list[str], dict[str, str]]:
    root = Path(clone_path).resolve()
    target = (root / finding_path).resolve()
    if root not in target.parents:
        raise ValueError("finding file path points outside the repository")
    content = target.read_text(encoding="utf-8") if target.is_file() else ""
    repo_files = [str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*")
                  if p.is_file() and ".git" not in p.parts]
    existing = {name: (root / name).read_text(encoding="utf-8") for name in SUPPORT_FILES if (root / name).is_file()}
    return content, repo_files, existing


def _already_handled(finding) -> bool:
    return any(getattr(f, "pr_url", None) or getattr(f, "branch", None) for f in (finding.fixes or []))


def handle_new_findings(db, repo_id: int, finding_ids: list[int]) -> None:
    """New findings from a push scan. For each new, live secret: generate a fix and open a PR.

    Never raises: one broken finding must not stop the others; every outcome is logged.
    """
    m = _models()
    repo = db.get(m.Repo, repo_id)
    if repo is None or not getattr(repo, "auto_fix_enabled", False):
        return   # contract 8.4: auto-fix is OFF unless the user turned it on

    todo = []
    for finding_id in finding_ids:
        finding = db.get(m.Finding, finding_id)
        if finding is None or finding.repo_id != repo_id:
            continue
        if _value(finding.type) != "secret" or finding.in_history_only or _value(finding.status) != "open":
            continue
        if _already_handled(finding):
            continue
        _log(db, repo_id, "detected", f"{finding.title} in {finding.file_path} line {finding.line}",
             finding_id=finding.id)
        todo.append(finding)

    if len(todo) > MAX_AUTO_FIXES_PER_PUSH:
        for finding in todo[MAX_AUTO_FIXES_PER_PUSH:]:
            _log(db, repo_id, "skipped", f"more than {MAX_AUTO_FIXES_PER_PUSH} new secrets in one push; "
                 "fix this one from the dashboard", finding_id=finding.id)
        todo = todo[:MAX_AUTO_FIXES_PER_PUSH]
    if not todo:
        return

    gh = _github()
    clone_path = None
    try:
        clone_path = gh.clone_repo(repo.full_name)
        for finding in todo:
            _fix_one(db, gh, repo, finding, clone_path)
    except Exception as exc:   # e.g. clone failed
        _log(db, repo_id, "error", f"auto-fix stopped: {type(exc).__name__}")
    finally:
        if clone_path:
            gh.cleanup_clone(clone_path)


def _fix_one(db, gh, repo, finding, clone_path: str) -> None:
    from app.ai.fix import generate_fix   # looked up on each call (tests replace it)
    m = _models()
    try:
        content, repo_files, existing = _read_repo(clone_path, finding.file_path)
        result = generate_fix(_finding_dict(finding), content, repo_files, existing_files=existing)
        ok = result["validation"].get("secret_removed") is True and result["validation"].get("syntax_ok") is True
        fix = m.Fix(finding_id=finding.id, explanation=result["explanation"], edits=result["edits"],
                    tier=result["tier"], validation=result["validation"],
                    status=m.FixStatus.generated if ok else m.FixStatus.validation_failed)
        db.add(fix)
        finding.status = m.FindingStatus.fix_proposed
        db.commit()
        db.refresh(fix)
        _log(db, repo.id, "fix_generated", f"tier {result['tier']}", finding_id=finding.id, fix_id=fix.id)

        if result["tier"] == "flag_only" or not result["edits"]:
            reason = (result["validation"]["notes"] or ["no safe automatic fix"])[-1]
            _log(db, repo.id, "skipped", f"no PR opened: {reason}", finding_id=finding.id, fix_id=fix.id)
            return

        opened = gh.open_fix_pr(db, fix.id)   # creates repoguard/fix-<finding_id>, sets branch
        if isinstance(opened, dict):
            pr_url = opened["pr_url"]
        elif isinstance(opened, (tuple, list)):
            pr_url = opened[0]
        else:   # the Fix object itself
            pr_url = getattr(opened, "pr_url", None) or fix.pr_url
        fix.ci_status = _ci("pending")
        db.commit()
        _log(db, repo.id, "pr_opened", pr_url, finding_id=finding.id, fix_id=fix.id)
        _log(db, repo.id, "ci_pending", "waiting for the repository's CI", finding_id=finding.id, fix_id=fix.id)
    except Exception as exc:
        db.rollback()
        _log(db, repo.id, "error", f"auto-fix failed: {type(exc).__name__}", finding_id=finding.id)


def _give_up(db, gh, fix, finding, full_name: str, why: str) -> None:
    fix.ci_status = _ci("failed")
    db.commit()
    _log(db, finding.repo_id, "gave_up", why, finding_id=finding.id, fix_id=fix.id, attempt=fix.repair_attempts)
    if fix.pr_number:
        try:
            gh.comment_on_pr(full_name, fix.pr_number, f"{NEEDS_HUMAN}\n\nReason: {why}")
        except Exception as exc:
            _log(db, finding.repo_id, "error", f"could not comment on the PR: {type(exc).__name__}",
                 finding_id=finding.id, fix_id=fix.id)


def handle_ci_result(db, fix_id: int, conclusion: str, log_text: str) -> None:
    """The repo's CI finished on a RepoGuard fix branch.

    success  -> ci_passed (a human merges; we never do)
    failure  -> repair the fix and push one commit to the same branch, at most MAX_REPAIR_ATTEMPTS
                times; after that, or if the repair is impossible, give up and ask for a human
    anything else (cancelled, skipped, timed_out, ...) -> logged, nothing changed
    The backend must only call this for the fix's latest commit (workflow_run.head_sha == fix.head_sha).
    """
    m = _models()
    fix = db.get(m.Fix, fix_id)
    if fix is None:
        return
    finding = fix.finding
    repo = finding.repo
    attempt = fix.repair_attempts or 0

    if conclusion == "success":
        fix.ci_status = _ci("passed")
        db.commit()
        _log(db, repo.id, "ci_passed", "CI passed; ready for a human to review and merge",
             finding_id=finding.id, fix_id=fix.id, attempt=attempt)
        return
    if conclusion != "failure":
        _log(db, repo.id, "error", f"CI ended with '{conclusion}'; nothing to repair",
             finding_id=finding.id, fix_id=fix.id, attempt=attempt)
        return

    errors = extract_ci_errors(log_text)
    fix.ci_status = _ci("failed")
    db.commit()
    _log(db, repo.id, "ci_failed", f"CI failed: {_error_summary(errors)}",
         finding_id=finding.id, fix_id=fix.id, attempt=attempt)

    gh = _github()
    expected_branch = f"{BRANCH_PREFIX}{finding.id}"
    if fix.branch != expected_branch:   # contract 8.4: only ever push to our own fix branch
        _log(db, repo.id, "error", f"refusing to push: branch is not {expected_branch}",
             finding_id=finding.id, fix_id=fix.id, attempt=attempt)
        return
    if attempt >= MAX_REPAIR_ATTEMPTS:
        _give_up(db, gh, fix, finding, repo.full_name, f"CI still fails after {attempt} repair(s).")
        return

    try:
        files = {path: text for path, text in
                 gh.get_branch_files(repo.full_name, fix.branch, [finding.file_path]).items() if text is not None}
        repaired = repair_fix(_finding_dict(finding), files, errors, list(files))
        if repaired["tier"] == "flag_only" or not repaired["edits"]:
            reason = (repaired["validation"]["notes"] or ["repair not possible"])[-1]
            _log(db, repo.id, "repair_failed", reason, finding_id=finding.id, fix_id=fix.id, attempt=attempt + 1)
            _give_up(db, gh, fix, finding, repo.full_name, reason)
            return

        edit = repaired["edits"][0]
        sha = gh.push_fix_commit(repo.full_name, fix.branch, repaired["edits"],
                                 f"RepoGuard: repair fix after CI failure ({_error_summary(errors)})")
        fix.repair_attempts = attempt + 1
        if sha:
            fix.head_sha = sha
        fix.ci_status = _ci("pending")
        # keep fix.edits = full change vs the default branch, so the dashboard diff stays right
        fix.edits = [dict(e, new_content=edit["new_content"]) if e["file_path"] == edit["file_path"] else e
                     for e in fix.edits]
        db.commit()
        _log(db, repo.id, "repaired", repaired["explanation"]["how_fixed"][:300],
             finding_id=finding.id, fix_id=fix.id, attempt=fix.repair_attempts)
        if fix.pr_number:
            gh.comment_on_pr(repo.full_name, fix.pr_number,
                             f"RepoGuard repaired this fix after CI failed (attempt {fix.repair_attempts}"
                             f"/{MAX_REPAIR_ATTEMPTS}).\n\n**Cause:** {repaired['explanation']['what']}\n"
                             f"**Change:** {repaired['explanation']['how_fixed']}")
    except Exception as exc:
        db.rollback()
        _log(db, repo.id, "error", f"repair failed: {type(exc).__name__}",
             finding_id=finding.id, fix_id=fix.id, attempt=attempt)