"""Try the self-healing repair with the REAL LLM on a broken fix (no GitHub, no database).

Scenario: the first AI fix used os.getenv() but forgot "import os", so the repo's CI failed
with NameError. We give repair_fix() the broken file + the CI log and print what it returns.

Run from the backend folder (needs backend/.env with your LLM keys, and Gitleaks):
    python -m scripts.try_repair
"""
import json
from pathlib import Path

from app.ai.agent import extract_ci_errors, repair_fix   # llm.py loads backend/.env

SAMPLES = Path(__file__).resolve().parent.parent / "tests" / "ai" / "samples"
FINDING = json.loads((SAMPLES / "findings.json").read_text(encoding="utf-8"))[0]
ORIGINAL = (SAMPLES / "config.py").read_text(encoding="utf-8")
SECRET = ORIGINAL.splitlines()[FINDING["line"] - 1][FINDING["start_column"] - 1:FINDING["end_column"]]
BROKEN = ORIGINAL.replace(f'"{SECRET}"', 'os.getenv("AWS_ACCESS_KEY_ID")')

CI_LOG = """\
2026-10-02T10:15:01.6000000Z >       from app import config
2026-10-02T10:15:01.7000000Z tests/test_app.py:3:
2026-10-02T10:15:01.9000000Z E   NameError: name 'os' is not defined
2026-10-02T10:15:02.0000000Z app/config.py:5: NameError
2026-10-02T10:15:02.2000000Z FAILED tests/test_app.py::test_s3_client - NameError: name 'os' is not defined
2026-10-02T10:15:02.3000000Z ========================= 1 failed, 1 passed in 0.12s ==========================
"""

errors = extract_ci_errors(CI_LOG)
print("CI error lines sent to the agent:")
for line in errors:
    print("  ", line)

result = repair_fix(FINDING, {"config.py": BROKEN}, errors, ["config.py"])
print("\ntier:", result["tier"])
print("cause:", result["explanation"]["what"])
print("how fixed:", result["explanation"]["how_fixed"])
for note in result["validation"]["notes"]:
    print("  -", note)
for edit in result["edits"]:
    print(f"\n--- {edit['file_path']} (repaired) ---\n{edit['new_content']}")