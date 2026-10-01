PENALTY = PENALTY = {"critical": 15, "high": 8, "medium": 4, "low": 2}

SECRET_CONTROLS = (["A07:2021"], ["V6.4.1"])   # TODO: verify against official docs
DEP_CONTROLS = (["A06:2021"], ["V14.2.1"])     # TODO: verify against official docs

CONTROLS = {
    "A07:2021": "Identification and Authentication Failures",
    "A06:2021": "Vulnerable and Outdated Components",
    "V6.4.1": "Secrets management",
    "V14.2.1": "Dependency management",
}


def map_controls(finding: dict) -> tuple[list[str], list[str]]:
    if finding.get("type") == "dependency":
        owasp, asvs = DEP_CONTROLS
    else:
        owasp, asvs = SECRET_CONTROLS
    return list(owasp), list(asvs)


def compute_compliance(findings: list[dict]) -> dict:
    total = 0.0
    by_control = {cid: [] for cid in CONTROLS}
    for f in findings:
        status = f.get("status")
        if status in ("false_positive", "fixed"):
            continue
        p = PENALTY.get(f.get("severity"), 0)
        if status == "needs_rotation":
            p = p / 2
        total += p
        ids = set(f.get("owasp_ids") or []) | set(f.get("asvs_ids") or [])
        for cid in ids:
            if cid in by_control:
                by_control[cid].append(f.get("id"))
    results = [
        {"control_id": cid, "name": name,
         "status": "fail" if by_control[cid] else "pass",
         "finding_ids": by_control[cid]}
        for cid, name in CONTROLS.items()
    ]
    return {"score": max(0, round(100 - total)), "control_results": results}