def compute_risk(repo_signals: dict, findings: list[dict]) -> dict:
    live = [f for f in findings if f.get("status") not in ("fixed", "false_positive")]
    open_secrets = [f for f in live if f.get("type") == "secret" and not f.get("in_history_only")]
    bad_deps = [f for f in live if f.get("type") == "dependency"
                and f.get("severity") in ("critical", "high")]
    contributors = repo_signals.get("contributor_count", 0)
    commits = repo_signals.get("commit_count_90d", 0)
    activity = min(1.0, (contributors / 10 + commits / 200) / 2)

    rows = [
        ("Open secrets in HEAD", len(open_secrets), 30, len(open_secrets) * 10),
        ("Historical secrets", repo_signals.get("historical_secret_count", 0), 15,
         repo_signals.get("historical_secret_count", 0) * 5),
        (".env tracked in repo", bool(repo_signals.get("env_file_tracked")), 15,
         15 if repo_signals.get("env_file_tracked") else 0),
        (".gitignore missing .env", repo_signals.get("gitignore_has_env") is False, 10,
         10 if repo_signals.get("gitignore_has_env") is False else 0),
        ("No pre-commit secret hook", repo_signals.get("has_precommit_secret_hook") is False, 5,
         5 if repo_signals.get("has_precommit_secret_hook") is False else 0),
        ("Vulnerable deps (critical/high)", len(bad_deps), 15, len(bad_deps) * 4),
        ("Contributors + commit rate", round(activity, 2), 10, activity * 10),
    ]
    factors = [
        {"name": n, "value": v, "weight": w, "contribution": round(min(c, w), 1)}
        for n, v, w, c in rows
    ]
    return {"score": min(100, round(sum(x["contribution"] for x in factors))),
            "factors": factors}