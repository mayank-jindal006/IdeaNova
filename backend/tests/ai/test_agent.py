"""Tests for the self-healing agent helpers (agent.py, Part 1).
The LLM is faked. Tests marked needs_gitleaks use the real Gitleaks binary."""
import json
import os
import shutil
from pathlib import Path

import pytest

from app.ai import agent
from app.ai.llm import LLMError
from app.ai.prompts import LOG_REDACTION_TOKEN

SAMPLES = Path(__file__).parent / "samples"
AWS = json.loads((SAMPLES / "findings.json").read_text(encoding="utf-8"))[0]
ORIGINAL = (SAMPLES / "config.py").read_text(encoding="utf-8")
AWS_SECRET = "AKIAUJZDEGXDNCF32EPF"
STRIPE_SECRET = (SAMPLES / "payments.py").read_text(encoding="utf-8").split('"')[1]

# What the fix branch looks like after a BAD first fix: os.getenv() used, "import os" forgotten.
BROKEN = ORIGINAL.replace(f'"{AWS_SECRET}"', 'os.getenv("AWS_ACCESS_KEY_ID")')
REPAIRED = BROKEN.replace('"""App configuration for the orders service."""\n',
                          '"""App configuration for the orders service."""\nimport os\n')

needs_gitleaks = pytest.mark.skipif(
    shutil.which(os.getenv("GITLEAKS_BIN", "gitleaks")) is None, reason="gitleaks not installed")

PYTEST_LOG = """\
2026-10-02T10:15:00.0000000Z ##[group]Run pytest
2026-10-02T10:15:00.1000000Z Collecting pytest==8.3.3
2026-10-02T10:15:00.2000000Z \x1b[1m============================= test session starts ==============================\x1b[0m
2026-10-02T10:15:01.0000000Z collected 2 items
2026-10-02T10:15:01.1000000Z
2026-10-02T10:15:01.2000000Z tests/test_app.py F.                                                      [100%]
2026-10-02T10:15:01.3000000Z =================================== FAILURES ===================================
2026-10-02T10:15:01.4000000Z ________________________________ test_s3_client ________________________________
2026-10-02T10:15:01.5000000Z     def test_s3_client():
2026-10-02T10:15:01.6000000Z >       from app import config
2026-10-02T10:15:01.7000000Z tests/test_app.py:3:
2026-10-02T10:15:01.8000000Z     AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
2026-10-02T10:15:01.9000000Z E   NameError: name 'os' is not defined
2026-10-02T10:15:02.0000000Z app/config.py:5: NameError
2026-10-02T10:15:02.1000000Z =========================== short test summary info ============================
2026-10-02T10:15:02.2000000Z FAILED tests/test_app.py::test_s3_client - NameError: name 'os' is not defined
2026-10-02T10:15:02.3000000Z ========================= 1 failed, 1 passed in 0.12s ==========================
2026-10-02T10:15:02.4000000Z ##[error]Process completed with exit code 1.
"""


# ---------- extract_ci_errors ----------

def test_extract_keeps_error_lines_and_drops_noise():
    errors = agent.extract_ci_errors(PYTEST_LOG)
    assert "E   NameError: name 'os' is not defined" in errors
    assert "app/config.py:5: NameError" in errors
    assert ">       from app import config" in errors
    assert any(e.startswith("FAILED tests/test_app.py::test_s3_client") for e in errors)
    assert "##[error]Process completed with exit code 1." in errors
    assert not any("Collecting" in e or "collected 2 items" in e for e in errors)


def test_extract_strips_timestamps_and_colours():
    for line in agent.extract_ci_errors(PYTEST_LOG):
        assert not line.startswith("2026-")
        assert "\x1b" not in line


def test_extract_keeps_python_traceback_source_line():
    log = ('Traceback (most recent call last):\n'
           '  File "app/config.py", line 5, in <module>\n'
           '    AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n'
           "KeyError: 'AWS_ACCESS_KEY_ID'\n")
    assert agent.extract_ci_errors(log) == log.splitlines()


def test_extract_node_errors():
    log = ("> node --test\n"
           "ReferenceError: proces is not defined\n"
           "    at Object.<anonymous> (/home/runner/work/app/index.js:3:15)\n"
           "npm ERR! Test failed.\n"
           "added 12 packages in 2s\n")
    errors = agent.extract_ci_errors(log)
    assert errors == ["ReferenceError: proces is not defined",
                      "    at Object.<anonymous> (/home/runner/work/app/index.js:3:15)",
                      "npm ERR! Test failed."]


def test_extract_limits_and_dedupes():
    log = "\n".join(f"E   AssertionError: case {i}" for i in range(100)) + "\nE   AssertionError: case 99\n"
    errors = agent.extract_ci_errors(log, max_lines=5)
    assert errors == [f"E   AssertionError: case {i}" for i in range(95, 100)]


def test_extract_only_reads_last_200_lines():
    log = "E   OldError: too early\n" + "ok\n" * 250 + "E   NewError: recent\n"
    assert agent.extract_ci_errors(log) == ["E   NewError: recent"]


def test_extract_empty_log():
    assert agent.extract_ci_errors("") == []
    assert agent.extract_ci_errors(None) == []


# ---------- repair_fix ----------

GOOD_REPAIR = {"fixable": True, "cause": "os was used without being imported.",
               "how_fixed": "Added import os.", "new_content": REPAIRED}
ERRORS = ["E   NameError: name 'os' is not defined", "app/config.py:5: NameError"]


@pytest.fixture
def fake_llm(monkeypatch):
    """Fake LLM; by default Gitleaks is faked too (no secrets found). Records every prompt."""
    calls = []

    def install(reply=None, error=None, real_gitleaks=False):
        replies = list(reply) if isinstance(reply, list) else None

        def fake(system, user, retries=2):
            calls.append(system + user)
            if error:
                raise error
            return replies.pop(0) if replies is not None else reply

        monkeypatch.setattr(agent, "complete_json", fake)
        if not real_gitleaks:
            monkeypatch.setattr(agent, "find_secrets", lambda path, content: [])
        return calls
    return install


def test_repair_adds_missing_import(fake_llm):
    calls = fake_llm(GOOD_REPAIR)
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, ["config.py"])
    assert result["tier"] == "pr_review"
    assert result["finding_id"] == AWS["id"]
    assert result["edits"] == [{"file_path": "config.py", "original_content": BROKEN, "new_content": REPAIRED}]
    assert result["validation"]["syntax_ok"] is True
    assert result["validation"]["secret_removed"] is True
    assert "NameError" in calls[0]                       # the CI error reached the LLM
    assert "import os" in result["explanation"]["how_fixed"]


def test_repair_not_fixable_is_flag_only(fake_llm):
    fake_llm({"fixable": False, "cause": "requests is not installed in CI.", "how_fixed": "", "new_content": ""})
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ["ModuleNotFoundError: No module named 'requests'"], [])
    assert result["tier"] == "flag_only"
    assert result["edits"] == []
    assert "requests is not installed" in result["explanation"]["how_fixed"]


def test_repair_that_removes_env_read_is_rejected(fake_llm):
    bad = dict(GOOD_REPAIR, new_content=REPAIRED.replace('os.getenv("AWS_ACCESS_KEY_ID")', "None"))
    calls = fake_llm([bad, bad])
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])
    assert result["tier"] == "flag_only"
    assert len(calls) == 2                               # retried once with the problem
    assert "REJECTED" in calls[1]


def test_repair_retry_succeeds(fake_llm):
    broken_syntax = dict(GOOD_REPAIR, new_content=REPAIRED.replace("def get_s3_client():", "def get_s3_client("))
    calls = fake_llm([broken_syntax, GOOD_REPAIR])
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])
    assert result["tier"] == "pr_review"
    assert "syntax error" in calls[1]
    assert any("second attempt" in n for n in result["validation"]["notes"])


def test_repair_too_large_is_rejected(fake_llm):
    rewrite = dict(GOOD_REPAIR, new_content="import os\n" + "\n".join(f"X{i} = {i}" for i in range(30))
                   + '\nAWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")\n')
    fake_llm(rewrite)
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])
    assert result["tier"] == "flag_only"
    assert any("too large" in n for n in result["validation"]["notes"])


def test_repair_unchanged_file_is_rejected(fake_llm):
    fake_llm(dict(GOOD_REPAIR, new_content=BROKEN))
    assert agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])["tier"] == "flag_only"


def test_repair_gates_do_not_call_llm(fake_llm):
    calls = fake_llm(GOOD_REPAIR)
    assert agent.repair_fix(AWS, {}, ERRORS, [])["tier"] == "flag_only"                       # file missing
    assert agent.repair_fix(AWS, {"config.py": BROKEN}, [], [])["tier"] == "flag_only"          # no errors
    assert agent.repair_fix(dict(AWS, type="dependency"), {"config.py": BROKEN}, ERRORS, [])["tier"] == "flag_only"
    yaml = dict(AWS, file_path="config.yaml")
    assert agent.repair_fix(yaml, {"config.yaml": "a: 1\n"}, ERRORS, [])["tier"] == "flag_only"
    # the original secret is back on the branch -> a human must look, the file is not sent
    assert agent.repair_fix(AWS, {"config.py": ORIGINAL}, ERRORS, [])["tier"] == "flag_only"
    assert calls == []


def test_repair_llm_down_is_flag_only(fake_llm):
    fake_llm(error=LLMError("down"))
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])
    assert result["tier"] == "flag_only"
    assert "not available" in result["explanation"]["how_fixed"]


def test_repair_without_gitleaks_never_calls_llm(fake_llm, monkeypatch):
    calls = fake_llm(GOOD_REPAIR)
    monkeypatch.setattr(agent, "find_secrets", lambda path, content: None)
    assert agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])["tier"] == "flag_only"
    assert calls == []


def test_repair_that_reintroduces_original_secret_is_rejected(fake_llm):
    leaked = dict(GOOD_REPAIR, new_content=REPAIRED.replace(
        'os.getenv("AWS_ACCESS_KEY_ID")', f'os.getenv("AWS_ACCESS_KEY_ID", "{AWS_SECRET}")'))
    fake_llm(leaked)
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])
    assert result["tier"] == "flag_only"
    assert any("adds a secret" in n for n in result["validation"]["notes"])


@needs_gitleaks
def test_other_secrets_never_reach_llm_from_file_or_log(fake_llm):
    """The fix branch still has a DIFFERENT secret (a separate finding), and the CI log
    quotes it. Neither copy may be sent; the repaired file must keep it unchanged."""
    other_line = f'\nSTRIPE_KEY = "{STRIPE_SECRET}"\n'
    branch = BROKEN + other_line
    errors = ERRORS + [f'    STRIPE_KEY = "{STRIPE_SECRET}"']

    def reply_from_prompt(system, user, retries=2):
        calls.append(user)
        sent = user.split("Current file content:\n", 1)[1]
        return dict(GOOD_REPAIR, new_content=sent.replace(
            '"""App configuration for the orders service."""\n',
            '"""App configuration for the orders service."""\nimport os\n'))

    calls = []
    fake_llm(real_gitleaks=True)
    agent.complete_json = reply_from_prompt   # monkeypatch fixture restores it after the test
    result = agent.repair_fix(AWS, {"config.py": branch}, errors, [])

    assert STRIPE_SECRET not in calls[0]
    assert "<<OTHER_SECRET_1>>" in calls[0]
    assert LOG_REDACTION_TOKEN in calls[0]
    assert result["tier"] == "pr_review", result["validation"]["notes"]
    assert result["edits"][0]["new_content"] == REPAIRED + other_line   # other secret restored as-is


@needs_gitleaks
def test_real_gitleaks_catches_new_secret(fake_llm):
    new_secret = dict(GOOD_REPAIR, new_content=REPAIRED + 'TOKEN = "ghp_JBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0RlgLK"\n')
    fake_llm(new_secret, real_gitleaks=True)
    result = agent.repair_fix(AWS, {"config.py": BROKEN}, ERRORS, [])
    assert result["tier"] == "flag_only"
    assert any("adds a secret" in n for n in result["validation"]["notes"])