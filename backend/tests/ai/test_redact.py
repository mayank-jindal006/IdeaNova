"""Tests for redact(): the real secret must never reach the LLM."""
import json
from pathlib import Path

import pytest

from app.ai.redact import REDACTION_TOKEN, redact

SAMPLES = Path(__file__).parent / "samples"
FINDINGS = json.loads((SAMPLES / "findings.json").read_text(encoding="utf-8"))


def load(finding):
    return (SAMPLES / finding["file_path"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("finding", FINDINGS, ids=[f["rule_id"] for f in FINDINGS])
def test_secret_is_gone_and_token_is_there(finding):
    original = load(finding)
    secret_line = original.splitlines()[finding["line"] - 1]
    secret = secret_line[finding["start_column"] - 1:finding["end_column"]]

    result = redact(original, finding)

    assert result is not None
    assert secret not in result
    assert REDACTION_TOKEN in result


@pytest.mark.parametrize("finding", FINDINGS, ids=[f["rule_id"] for f in FINDINGS])
def test_only_the_secret_line_changes(finding):
    original = load(finding).splitlines()
    result = redact(load(finding), finding).splitlines()

    assert len(result) == len(original)
    for i, (before, after) in enumerate(zip(original, result), start=1):
        if i != finding["line"]:
            assert before == after


def test_wrong_columns_are_refused():
    finding = dict(FINDINGS[0], start_column=FINDINGS[0]["start_column"] + 1,
                   end_column=FINDINGS[0]["end_column"] + 1)   # off by one
    assert redact(load(FINDINGS[0]), finding) is None


def test_missing_columns_are_refused():
    finding = dict(FINDINGS[0], start_column=None, end_column=None)
    assert redact(load(FINDINGS[0]), finding) is None


def test_line_out_of_range_is_refused():
    finding = dict(FINDINGS[0], line=999)
    assert redact(load(FINDINGS[0]), finding) is None


def test_windows_line_endings_are_kept():
    content = 'x = 1\r\nKEY = "AKIAUJZDEGXDNCF32EPF"\r\ny = 2\r\n'
    finding = {"line": 2, "start_column": 8, "end_column": 27, "secret_masked": "AKIA****2EPF"}
    assert redact(content, finding) == f'x = 1\r\nKEY = "{REDACTION_TOKEN}"\r\ny = 2\r\n'

# ---------- same secret appearing more than once (e.g. password + database URL) ----------

DB_FILE = ('DB_PASSWORD = "xK9mQ2wLp7ZtR5vNc8Yd"\n'
           '\n'
           'DATABASE_URL = "postgresql://appuser:xK9mQ2wLp7ZtR5vNc8Yd@db.example.io:5432/appdb"\n')
DB_FINDING = {"line": 1, "start_column": 16, "end_column": 35, "secret_masked": "xK9m****c8Yd"}


def test_every_copy_of_the_secret_is_hidden():
    result = redact(DB_FILE, DB_FINDING)
    assert "xK9mQ2wLp7ZtR5vNc8Yd" not in result
    assert result.count(REDACTION_TOKEN) == 2
    assert "postgresql://appuser:" + REDACTION_TOKEN + "@db.example.io" in result