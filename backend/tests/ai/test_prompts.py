"""Tests for prompts.py: the prompt must contain what the LLM needs, and never a real secret."""
import json
from pathlib import Path

from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from app.ai.redact import REDACTION_TOKEN, redact

SAMPLES = Path(__file__).parent / "samples"
FINDINGS = json.loads((SAMPLES / "findings.json").read_text(encoding="utf-8"))


def test_system_prompt_describes_the_reply_format():
    for field in ("env_var_name", "explanation", "new_content"):
        assert field in SYSTEM_PROMPT


def test_user_prompt_has_token_and_file_but_no_real_secret():
    finding = FINDINGS[0]  # AWS key in config.py
    original = (SAMPLES / finding["file_path"]).read_text(encoding="utf-8")
    real_secret = original.splitlines()[finding["line"] - 1][finding["start_column"] - 1:finding["end_column"]]

    prompt = build_user_prompt(finding, redact(original, finding), "python", ["config.py", "app.py"])

    assert REDACTION_TOKEN in prompt
    assert "config.py" in prompt
    assert real_secret not in prompt