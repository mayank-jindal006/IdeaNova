"""Decide how much a fix can be trusted: auto_branch, pr_review or flag_only.

Rules (plan section 6.2), made concrete:
  flag_only   -- confidence below 0.6, or the fix failed validation, or there is no code change.
                 (Decided in fix.py before/after calling the LLM; no edits are proposed.)
  auto_branch -- validation passed, confidence >= 0.85, AND the change to the affected file is
                 tiny and mechanical (at most AUTO_MAX_CHANGED_LINES lines, e.g. the secret line
                 plus "import os"). Still only a branch + PR: nothing is ever merged automatically.
  pr_review   -- everything else that passed validation: a human reviews the PR.

Confidence starts from the scanner's value and is lowered for signs of a false positive.
"""
import difflib

AUTO_MIN_CONFIDENCE = 0.85
REVIEW_MIN_CONFIDENCE = 0.6
AUTO_MAX_CHANGED_LINES = 2

# Generic rules match "anything that looks random", so they produce more false positives
# than provider-specific rules (aws-access-token, stripe-access-token, github-pat, ...).
GENERIC_RULE_FACTOR = 0.8
# Secrets in test/example code are often deliberate dummies.
TEST_PATH_FACTOR = 0.6
TEST_PATH_WORDS = ("test", "tests", "example", "examples", "sample", "samples", "mock", "mocks",
                   "fixture", "fixtures", "demo", "spec")


def _path_parts(file_path: str) -> list[str]:
    parts = file_path.replace("\\", "/").lower().split("/")
    words = []
    for part in parts:
        stem = part.rsplit(".", 1)[0]
        words.extend(stem.replace("-", "_").split("_"))
    return words


def adjusted_confidence(finding: dict) -> float:
    confidence = float(finding.get("confidence") if finding.get("confidence") is not None else 1.0)
    if "generic" in (finding.get("rule_id") or "").lower():
        confidence *= GENERIC_RULE_FACTOR
    if any(word in TEST_PATH_WORDS for word in _path_parts(finding.get("file_path") or "")):
        confidence *= TEST_PATH_FACTOR
    return round(max(0.0, min(1.0, confidence)), 2)


def changed_lines(original: str, new: str) -> int:
    """Number of lines added or removed-and-replaced (a modified line counts once)."""
    old_lines, new_lines = original.splitlines(), new.splitlines()
    changed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old_lines, new_lines).get_opcodes():
        if tag != "equal":
            changed += max(i2 - i1, j2 - j1)
    return changed


def assign_tier(finding: dict, main_edit: dict, confidence: float) -> str:
    """Tier for a fix that already passed validation."""
    small = changed_lines(main_edit["original_content"], main_edit["new_content"]) <= AUTO_MAX_CHANGED_LINES
    if confidence >= AUTO_MIN_CONFIDENCE and small:
        return "auto_branch"
    return "pr_review"