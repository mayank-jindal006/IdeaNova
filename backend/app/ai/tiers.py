from __future__ import annotations


def assign_tier(finding: dict, fix: dict) -> str:
    if finding["in_history_only"] or finding["confidence"] < 0.6 or not fix["validation"]["secret_removed"] or not fix["validation"]["syntax_ok"]:
        return "flag_only"
    config_files = {".env", ".env.example", ".gitignore", "config.py", "config.js"}
    touched = {edit["file_path"].split("/")[-1] for edit in fix["edits"]}
    if finding["type"] == "secret" and finding["confidence"] >= 0.85 and touched.issubset(config_files):
        return "auto_branch"
    return "pr_review"
