from __future__ import annotations


def compute_risk(repo_signals: dict, findings: list[dict]) -> dict:
    """Contractual transparent heuristic. Every contribution is returned to the UI."""
    open_secrets = sum(1 for finding in findings if finding["type"] == "secret" and not finding["in_history_only"] and finding["status"] == "open")
    vulnerable_deps = sum(1 for finding in findings if finding["type"] == "dependency" and finding["severity"] in {"critical", "high"} and finding["status"] == "open")
    commit_factor = 10 if repo_signals["contributor_count"] >= 5 and repo_signals["commit_count_90d"] >= 50 else 0
    factors = [
        {"name": "Open secrets in HEAD", "value": open_secrets, "weight": 10, "contribution": min(30, open_secrets * 10)},
        {"name": "Historical secrets", "value": repo_signals["historical_secret_count"], "weight": 5, "contribution": min(15, repo_signals["historical_secret_count"] * 5)},
        {"name": ".env tracked in repo", "value": repo_signals["env_file_tracked"], "weight": 15, "contribution": 15 if repo_signals["env_file_tracked"] else 0},
        {"name": ".gitignore missing .env", "value": not repo_signals["gitignore_has_env"], "weight": 10, "contribution": 0 if repo_signals["gitignore_has_env"] else 10},
        {"name": "No pre-commit secret hook", "value": not repo_signals["has_precommit_secret_hook"], "weight": 5, "contribution": 0 if repo_signals["has_precommit_secret_hook"] else 5},
        {"name": "Vulnerable dependencies", "value": vulnerable_deps, "weight": 4, "contribution": min(15, vulnerable_deps * 4)},
        {"name": "Many contributors + high commit rate", "value": repo_signals["contributor_count"], "weight": 10, "contribution": commit_factor},
    ]
    return {"score": min(100, sum(factor["contribution"] for factor in factors)), "factors": factors}
