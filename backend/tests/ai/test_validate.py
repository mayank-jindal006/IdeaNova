"""Tests for validate.py. These run the REAL Gitleaks and Node (skipped if not installed)."""
import os
import shutil
from pathlib import Path

import pytest

from app.ai.validate import check_syntax, passed, validate_fix

SAMPLES = Path(__file__).parent / "samples"
CONFIG = (SAMPLES / "config.py").read_text(encoding="utf-8")
INDEX_JS = (SAMPLES / "index.js").read_text(encoding="utf-8")
REAL_AWS = "AKIAUJZDEGXDNCF32EPF"
REAL_GH = "ghp_JBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0RlgLK"

needs_gitleaks = pytest.mark.skipif(shutil.which(os.getenv("GITLEAKS_BIN", "gitleaks")) is None,
                                     reason="gitleaks not installed")
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def edit(path, content):
    return {"file_path": path, "original_content": "", "new_content": content}


# ---------- syntax (no external tools needed for Python) ----------

def test_valid_python_passes():
    ok, _ = check_syntax("config.py", CONFIG)
    assert ok is True


def test_broken_python_fails_with_line_number():
    ok, note = check_syntax("config.py", "x = os.getenv(\"KEY\"\n")
    assert ok is False
    assert "line" in note


def test_unknown_language_is_not_a_pass():
    ok, _ = check_syntax("main.go", "package main")
    assert ok is None


@needs_node
def test_valid_js_passes():
    ok, _ = check_syntax("index.js", INDEX_JS.replace(f'"{REAL_GH}"', "process.env.GITHUB_TOKEN"))
    assert ok is True


@needs_node
def test_broken_js_fails():
    ok, _ = check_syntax("index.js", "const a = ;\n")
    assert ok is False


# ---------- secret removal (real Gitleaks) ----------

@needs_gitleaks
def test_secret_still_there_fails():
    result = validate_fix([edit("config.py", CONFIG)], "config.py")
    assert result["secret_removed"] is False
    assert not passed(result)


@needs_gitleaks
def test_secret_removed_passes():
    fixed = CONFIG.replace(f'"{REAL_AWS}"', 'os.getenv("AWS_ACCESS_KEY_ID")')
    result = validate_fix([edit("config.py", fixed), edit(".env.example", "AWS_ACCESS_KEY_ID=\n")], "config.py")
    assert result["secret_removed"] is True
    assert result["syntax_ok"] is True
    assert passed(result)


@needs_gitleaks
def test_notes_never_contain_the_secret():
    result = validate_fix([edit("config.py", CONFIG)], "config.py")
    assert all(REAL_AWS not in note for note in result["notes"])


@needs_gitleaks
def test_nested_path_works():
    fixed = CONFIG.replace(f'"{REAL_AWS}"', 'os.getenv("AWS_ACCESS_KEY_ID")')
    result = validate_fix([edit("app/config.py", fixed)], "app/config.py")
    assert passed(result)


def test_missing_main_file_edit_fails():
    result = validate_fix([edit(".env.example", "X=\n")], "config.py")
    assert result["secret_removed"] is False


def test_path_escaping_the_folder_is_refused():
    result = validate_fix([edit("../../evil.py", "x = 1\n")], "../../evil.py")
    assert result["secret_removed"] is None

# ---------- a file with TWO different secrets: fixing one must not fail because of the other ----------

TWO_SECRETS = ('AWS_ACCESS_KEY_ID = "AKIAUJZDEGXDNCF32EPF"\n'
               'GITHUB_TOKEN = "ghp_JBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0RlgLK"\n')


@needs_gitleaks
def test_other_secret_in_same_file_does_not_fail_this_fix():
    fixed = TWO_SECRETS.replace('"AKIAUJZDEGXDNCF32EPF"', 'os.getenv("AWS_ACCESS_KEY_ID")')
    result = validate_fix([edit("config.py", "import os\n" + fixed)], "config.py", secret=REAL_AWS)
    assert result["secret_removed"] is True
    assert any("other secret" in note for note in result["notes"])
    assert all(REAL_GH not in note and REAL_AWS not in note for note in result["notes"])


@needs_gitleaks
def test_this_secret_still_there_fails_even_if_other_was_fixed():
    fixed = TWO_SECRETS.replace(f'"{REAL_GH}"', 'os.getenv("GITHUB_TOKEN")')
    result = validate_fix([edit("config.py", "import os\n" + fixed)], "config.py", secret=REAL_AWS)
    assert result["secret_removed"] is False


def test_secret_value_still_in_fix_fails_without_gitleaks():
    # e.g. the password left inside a URL that Gitleaks doesn't recognise
    content = 'URL = "postgresql://u:xK9mQ2wLp7ZtR5vNc8Yd@host/db"\n'
    result = validate_fix([edit("db.py", content)], "db.py", secret="xK9mQ2wLp7ZtR5vNc8Yd")
    assert result["secret_removed"] is False
    assert all("xK9mQ2wLp7ZtR5vNc8Yd" not in note for note in result["notes"])