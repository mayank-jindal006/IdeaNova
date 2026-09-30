"""Run generate_fix on the 3 sample findings with the REAL LLM. Run from the backend folder."""
import json
import time
from pathlib import Path

from app.ai.fix import generate_fix

SAMPLES = Path("tests/ai/samples")
findings = json.loads((SAMPLES / "findings.json").read_text(encoding="utf-8"))
repo_files = [p.name for p in SAMPLES.iterdir() if p.is_file()]

results = []
for finding in findings:
    content = (SAMPLES / finding["file_path"]).read_text(encoding="utf-8")
    start = time.time()
    result = generate_fix(finding, content, repo_files)
    results.append(result)

    print("=" * 70)
    print(f"{finding['rule_id']} in {finding['file_path']}: tier={result['tier']} ({time.time() - start:.1f}s)")
    print("How fixed:", result["explanation"]["how_fixed"])
    if result["validation"]["notes"]:
        print("Notes:", result["validation"]["notes"])
    for edit in result["edits"]:
        print(f"--- {edit['file_path']} ---")
        print(edit["new_content"])
    time.sleep(2)   # stay well under the free-tier rate limit

Path("fix_examples.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print("\nSaved all 3 Fix objects to fix_examples.json")