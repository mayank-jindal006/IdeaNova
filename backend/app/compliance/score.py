from __future__ import annotations

_CONTROL_NAMES = {
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "V6.4.1": "ASVS Credential Management",
    "V14.2.1": "ASVS Dependency Security",
}


def map_controls(finding: dict) -> tuple[list[str], list[str]]:
    if finding["type"] == "dependency":
        return ["A06:2021"], ["V14.2.1"]
    return ["A07:2021"], ["V6.4.1"]


def compute_compliance(findings: list[dict]) -> dict:
    penalties = {"critical": 25, "high": 15, "medium": 7, "low": 3}
    score = 100
    controls: dict[str, list[int]] = {}
    for finding in findings:
        if finding["status"] in {"false_positive", "fixed"}:
            continue
        penalty = penalties.get(finding.get("severity"), 0)
        if finding["status"] == "needs_rotation":
            penalty /= 2
        score -= penalty
        for control_id in finding.get("owasp_ids", []) + finding.get("asvs_ids", []):
            controls.setdefault(control_id, []).append(finding["id"])
    return {
        "score": max(0, round(score)),
        "control_results": [
            {"control_id": control_id, "name": _CONTROL_NAMES.get(control_id, control_id), "status": "fail", "finding_ids": finding_ids}
            for control_id, finding_ids in sorted(controls.items())
        ],
    }
