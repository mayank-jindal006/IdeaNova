from __future__ import annotations

from typing import Any


_SEVERITY_POINTS = {"critical": 40, "high": 30, "medium": 20, "low": 10}


def assess_finding_risk(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic priority score and its evidence, not an exploitability claim."""
    severity = str(finding.get("severity") or "").lower()
    severity_points = _SEVERITY_POINTS.get(severity, 0)
    secret_points = 15 if finding.get("type") == "secret" else 0
    history_points = 10 if finding.get("in_history_only") else 0
    remediation_points = 5 if finding.get("fixed_version") else 0
    score = min(100, severity_points + secret_points + history_points + remediation_points)
    priority = "critical" if score >= 70 else "high" if score >= 50 else "medium" if score >= 30 else "low"
    factors = [
        {"factor": "scanner_severity", "evidence": severity or "not_provided", "points": severity_points},
        {"factor": "finding_type", "evidence": finding.get("type") or "not_provided", "points": secret_points},
        {
            "factor": "repository_history",
            "evidence": "historical" if finding.get("in_history_only") else "current_or_unknown",
            "points": history_points,
        },
        {
            "factor": "verified_fixed_version",
            "evidence": "available" if finding.get("fixed_version") else "not_available",
            "points": remediation_points,
        },
    ]
    return {
        "score": score,
        "priority": priority,
        "method": "deterministic",
        "exploitability": "unknown; scanner metadata does not establish reachability or active exploitation",
        "factors": factors,
    }
