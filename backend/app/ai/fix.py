from __future__ import annotations

from app.ai.explain import explain_finding
from app.ai.llm import LLMError, complete_json
from app.ai.redaction import redact_context_for_llm
from app.ai.tiers import assign_tier


def generate_fix(finding: dict, file_content: str, repo_files: list[str]) -> dict:
    """Return the contractual Fix object; source context is redacted before the provider call."""
    explanation = explain_finding(finding)
    fix = {"finding_id": finding["id"], "explanation": explanation, "edits": [], "tier": "flag_only", "validation": {"secret_removed": False, "syntax_ok": False, "notes": ["Fix generation requires the affected source file and a configured LLM provider."]}}
    if len(file_content.splitlines()) <= 300:
        safe_content = redact_context_for_llm(file_content, [])
        prompt = {"finding": finding, "file_content": safe_content, "repo_files": repo_files, "required_output": "Fix object with explanation, full-file edits, tier, validation. Never include a real secret value."}
        try:
            generated = complete_json("Return only the RepoGuard Fix JSON object. Never reveal secrets.", str(prompt))
            generated["finding_id"] = finding["id"]
            fix = generated
        except (LLMError, ValueError, KeyError, TypeError):
            pass
    fix["tier"] = assign_tier(finding, fix)
    return fix
