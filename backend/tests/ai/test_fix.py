"""Tests for generate_fix(). The LLM is faked, so these are free and need no internet."""
import json
from pathlib import Path

import os
import shutil

import pytest

from app.ai import fix
from app.ai.llm import LLMError
from app.ai.redact import REDACTION_TOKEN

SAMPLES = Path(__file__).parent / "samples"
FINDINGS = json.loads((SAMPLES / "findings.json").read_text(encoding="utf-8"))
AWS = FINDINGS[0]
CONTENT = (SAMPLES / "config.py").read_text(encoding="utf-8")
REAL_SECRET = CONTENT.splitlines()[AWS["line"] - 1][AWS["start_column"] - 1:AWS["end_column"]]

GOOD_REPLY = {
    "env_var_name": "AWS_ACCESS_KEY_ID",
    "explanation": {"what": "AWS key in config.py.", "why_dangerous": "Anyone can use it.",
                    "how_fixed": "Read from env var."},
    "new_content": CONTENT.replace(f'"{REAL_SECRET}"', 'os.getenv("AWS_ACCESS_KEY_ID")'),
}


PASS = {"secret_removed": True, "syntax_ok": True, "notes": ["ok"]}
FAIL = {"secret_removed": False, "syntax_ok": True, "notes": ["Gitleaks still finds a secret in config.py."]}


@pytest.fixture
def fake_llm(monkeypatch):
    """Replace the real LLM (and, by default, the validator). Records every prompt sent.

    reply   -- one reply, or a list of replies for successive calls
    results -- list of validation results for successive validate_fix calls (default: always pass)
    """
    calls = []

    def install(reply=None, error=None, results=None, real_gitleaks=False):
        replies = list(reply) if isinstance(reply, list) else None
        checks = list(results) if results else None

        def fake(system, user, retries=2):
            calls.append(system + user)
            if error:
                raise error
            return replies.pop(0) if replies is not None else reply

        def fake_validate(edits, main_file, secret=None):
            return checks.pop(0) if checks else PASS

        monkeypatch.setattr(fix, "complete_json", fake)
        monkeypatch.setattr(fix, "validate_fix", fake_validate)
        if not real_gitleaks:
            monkeypatch.setattr(fix, "find_secrets", lambda path, content: [])
        return calls
    return install


def test_happy_path_builds_full_fix(fake_llm):
    calls = fake_llm(GOOD_REPLY)
    result = fix.generate_fix(AWS, CONTENT, ["config.py"])

    assert result["finding_id"] == AWS["id"]
    assert result["tier"] == "auto_branch"          # 1-line mechanical change, confidence 0.9
    assert result["explanation"]["rotation_required"] is True
    assert "AWS IAM" in result["explanation"]["rotation_note"]
    paths = [e["file_path"] for e in result["edits"]]
    assert paths == ["config.py", ".env.example", ".gitignore"]
    assert result["edits"][1]["new_content"] == "AWS_ACCESS_KEY_ID=\n"
    assert result["edits"][2]["new_content"] == ".env\n"
    assert REAL_SECRET not in calls[0]          # the real key was never sent


def test_existing_gitignore_is_appended_not_overwritten(fake_llm):
    fake_llm(GOOD_REPLY)
    result = fix.generate_fix(AWS, CONTENT, ["config.py", ".gitignore"],
                              existing_files={".gitignore": "node_modules"})
    gitignore = [e for e in result["edits"] if e["file_path"] == ".gitignore"][0]
    assert gitignore["original_content"] == "node_modules"
    assert gitignore["new_content"] == "node_modules\n.env\n"


def test_gitignore_already_has_env_means_no_edit(fake_llm):
    fake_llm(GOOD_REPLY)
    result = fix.generate_fix(AWS, CONTENT, ["config.py", ".gitignore"],
                              existing_files={".gitignore": "node_modules\n.env\n"})
    assert ".gitignore" not in [e["file_path"] for e in result["edits"]]


def test_unknown_gitignore_content_is_never_overwritten(fake_llm):
    fake_llm(GOOD_REPLY)
    result = fix.generate_fix(AWS, CONTENT, ["config.py", ".gitignore"])   # exists, content not given
    assert ".gitignore" not in [e["file_path"] for e in result["edits"]]
    assert any(".gitignore" in n for n in result["validation"]["notes"])


def test_wrong_columns_means_flag_only_and_llm_not_called(fake_llm):
    calls = fake_llm(GOOD_REPLY)
    bad = dict(AWS, start_column=AWS["start_column"] + 1, end_column=AWS["end_column"] + 1)
    result = fix.generate_fix(bad, CONTENT, ["config.py"])
    assert result["tier"] == "flag_only"
    assert result["edits"] == []
    assert calls == []


def test_unsupported_language_is_flag_only(fake_llm):
    calls = fake_llm(GOOD_REPLY)
    result = fix.generate_fix(dict(AWS, file_path="main.go"), CONTENT, ["main.go"])
    assert result["tier"] == "flag_only"
    assert calls == []


def test_token_left_in_reply_is_flag_only(fake_llm):
    fake_llm(dict(GOOD_REPLY, new_content=f'KEY = "{REDACTION_TOKEN}"\n'))
    assert fix.generate_fix(AWS, CONTENT, ["config.py"])["tier"] == "flag_only"


def test_bad_env_var_name_is_flag_only(fake_llm):
    fake_llm(dict(GOOD_REPLY, env_var_name="my key"))
    assert fix.generate_fix(AWS, CONTENT, ["config.py"])["tier"] == "flag_only"


def test_llm_down_is_flag_only(fake_llm):
    fake_llm(error=LLMError("503"))
    result = fix.generate_fix(AWS, CONTENT, ["config.py"])
    assert result["tier"] == "flag_only"
    assert result["explanation"]["rotation_required"] is True


def test_windows_line_endings_are_kept(fake_llm):
    crlf = CONTENT.replace("\n", "\r\n")
    fake_llm(GOOD_REPLY)   # LLM replies with \n
    result = fix.generate_fix(AWS, crlf, ["config.py"])
    assert result["edits"][0]["new_content"] == GOOD_REPLY["new_content"].replace("\n", "\r\n")

def test_validation_result_is_included(fake_llm):
    fake_llm(GOOD_REPLY)
    result = fix.generate_fix(AWS, CONTENT, ["config.py"])
    assert result["validation"]["secret_removed"] is True
    assert result["validation"]["syntax_ok"] is True


def test_failed_validation_retries_once_with_the_error(fake_llm):
    calls = fake_llm([GOOD_REPLY, GOOD_REPLY], results=[FAIL, PASS])
    result = fix.generate_fix(AWS, CONTENT, ["config.py"])
    assert len(calls) == 2
    assert "REJECTED BY OUR CHECKS" in calls[1]
    assert "Gitleaks still finds a secret" in calls[1]
    assert REAL_SECRET not in calls[1]          # the retry never leaks the key either
    assert result["tier"] in ("auto_branch", "pr_review")
    assert any("second attempt" in n for n in result["validation"]["notes"])


def test_failing_twice_is_flag_only_with_no_edits(fake_llm):
    calls = fake_llm([GOOD_REPLY, GOOD_REPLY], results=[FAIL, FAIL])
    result = fix.generate_fix(AWS, CONTENT, ["config.py"])
    assert len(calls) == 2
    assert result["tier"] == "flag_only"
    assert result["edits"] == []
    assert any("did not pass validation" in n for n in result["validation"]["notes"])


def test_bad_reply_then_good_reply_recovers(fake_llm):
    calls = fake_llm([dict(GOOD_REPLY, env_var_name="my key"), GOOD_REPLY])
    result = fix.generate_fix(AWS, CONTENT, ["config.py"])
    assert len(calls) == 2
    assert result["tier"] in ("auto_branch", "pr_review")

def test_bigger_change_needs_review(fake_llm):
    rewritten = GOOD_REPLY["new_content"].replace('BUCKET_NAME = "orders-invoices"',
                                                  'BUCKET_NAME = os.getenv("BUCKET")\nREGION = os.getenv("REGION")')
    fake_llm(dict(GOOD_REPLY, new_content="import os\n" + rewritten))
    assert fix.generate_fix(AWS, CONTENT, ["config.py"])["tier"] == "pr_review"


def test_generic_rule_needs_review(fake_llm):
    fake_llm(GOOD_REPLY)
    generic = dict(AWS, rule_id="generic-api-key", confidence=1.0)
    assert fix.generate_fix(generic, CONTENT, ["config.py"])["tier"] == "pr_review"   # 0.8 < 0.85


def test_secret_in_test_file_is_flag_only_and_llm_not_called(fake_llm):
    calls = fake_llm(GOOD_REPLY)
    in_tests = dict(AWS, file_path="tests/test_config.py", confidence=0.9)   # 0.9 * 0.6 = 0.54
    result = fix.generate_fix(in_tests, CONTENT, ["tests/test_config.py"])
    assert result["tier"] == "flag_only"
    assert result["edits"] == []
    assert calls == []

def test_repeated_secret_is_never_sent_to_the_llm(fake_llm):
    content = ('import os\n'
               'DB_PASSWORD = "xK9mQ2wLp7ZtR5vNc8Yd"\n'
               'DATABASE_URL = "postgresql://appuser:xK9mQ2wLp7ZtR5vNc8Yd@db.example.io:5432/appdb"\n')
    finding = dict(AWS, rule_id="generic-api-key", file_path="db.py", line=2,
                   start_column=16, end_column=35, secret_masked="xK9m****c8Yd")
    calls = fake_llm(GOOD_REPLY)
    fix.generate_fix(finding, content, ["db.py"])
    assert calls and all("xK9mQ2wLp7ZtR5vNc8Yd" not in c for c in calls)



@pytest.mark.skipif(shutil.which(os.getenv("GITLEAKS_BIN", "gitleaks")) is None, reason="gitleaks not installed")
def test_other_secret_in_same_file_is_hidden_and_restored(fake_llm):
    gh = "ghp_JBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0RlgLK"
    content = CONTENT.replace('BUCKET_NAME = "orders-invoices"', f'GITHUB_TOKEN = "{gh}"')
    reply_content = content.replace(f'"{REAL_SECRET}"', 'os.getenv("AWS_ACCESS_KEY_ID")').replace(gh, "<<OTHER_SECRET_1>>")
    calls = fake_llm(dict(GOOD_REPLY, new_content=reply_content), real_gitleaks=True)
    result = fix.generate_fix(AWS, content, ["config.py"])
    assert calls and all(gh not in c and REAL_SECRET not in c for c in calls)   # neither secret sent
    assert "<<OTHER_SECRET_1>>" in calls[0]
    assert gh in result["edits"][0]["new_content"]                               # other secret put back
    assert "<<OTHER_SECRET" not in result["edits"][0]["new_content"]


def test_ai_removing_other_placeholder_is_rejected(fake_llm, monkeypatch):
    fake_llm(GOOD_REPLY)
    monkeypatch.setattr(fix, "find_secrets", lambda path, content: ["orders-invoices-secret-value"])
    content = CONTENT.replace('"orders-invoices"', '"orders-invoices-secret-value"')
    result = fix.generate_fix(AWS, content, ["config.py"])          # GOOD_REPLY drops the placeholder
    assert result["tier"] == "flag_only"
    assert any("OTHER_SECRET_1" in n for n in result["validation"]["notes"])