import hashlib
import json
from pathlib import Path
from urllib.parse import quote

import httpx

from app.config import get_settings


def _dependencies(root: Path) -> list[dict]:
    dependencies = []
    requirements = root / "requirements.txt"
    if requirements.exists():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "==" in line:
                name, version = line.split("==", 1)
                dependencies.append({"name": name.strip(), "version": version.strip(), "ecosystem": "PyPI", "file_path": "requirements.txt"})
    package_json = root / "package.json"
    if package_json.exists():
        data = json.loads(package_json.read_text(encoding="utf-8"))
        for group in ("dependencies", "devDependencies"):
            for name, version in data.get(group, {}).items():
                dependencies.append({"name": name, "version": str(version).lstrip("^~"), "ecosystem": "npm", "file_path": "package.json"})
    return dependencies


def _severity(vulnerability: dict) -> str:
    for severity in vulnerability.get("severity", []):
        score = severity.get("score", "")
        if "CRITICAL" in score.upper() or score.startswith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"):
            return "critical"
        if score:
            return "high"
    return "medium"


def _fixed_version(vulnerability: dict) -> str | None:
    for affected in vulnerability.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("fixed"):
                    return event["fixed"]
    return None


def _enrich_vulnerability(vulnerability: dict) -> dict:
    """Fetch the full OSV record when querybatch returns an ID-only reference."""
    if vulnerability.get("severity") or vulnerability.get("affected"):
        return vulnerability
    vuln_id = vulnerability.get("id")
    if not vuln_id:
        return vulnerability
    api_url = get_settings().osv_api_url
    details_url = f"{api_url.rsplit('/querybatch', 1)[0]}/vulns/{quote(vuln_id, safe='')}"
    try:
        response = httpx.get(details_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError:
        # Preserve the querybatch result when enrichment is temporarily unavailable.
        return vulnerability


def scan_dependencies(repo_path: str) -> list[dict]:
    dependencies = _dependencies(Path(repo_path))
    if not dependencies:
        return []
    results = httpx.post(get_settings().osv_api_url, json={"queries": [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in dependencies]}, timeout=30).json().get("results", [])
    findings = []
    for dependency, result in zip(dependencies, results):
        for vulnerability in result.get("vulns", []):
            vulnerability = _enrich_vulnerability(vulnerability)
            rule_id = vulnerability.get("id", "OSV")
            fingerprint = hashlib.sha256(f"{rule_id}{dependency['name']}{dependency['version']}".encode()).hexdigest()
            findings.append({"type": "dependency", "rule_id": rule_id, "title": vulnerability.get("summary") or rule_id,
                "severity": _severity(vulnerability), "file_path": dependency["file_path"], "line": None, "commit_sha": None,
                "secret_masked": None, "secret_hash": None, "package": dependency["name"], "ecosystem": dependency["ecosystem"],
                "installed_version": dependency["version"], "fixed_version": _fixed_version(vulnerability), "in_history_only": False,
                "confidence": 1.0, "status": "open", "owasp_ids": [], "asvs_ids": [], "fingerprint": fingerprint})
    return findings
