from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from app.core.scan_paths import validate_scan_path
from app.settings import settings

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns"
_EXACT_VERSION = re.compile(r"^[0-9]+(?:[A-Za-z0-9._+!\-]*)(?:\.[A-Za-z0-9._+!\-]+)*$")


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str


@dataclass(frozen=True, slots=True)
class DependencyScanResult:
    findings: list[dict[str, Any]]
    status: str
    reason: str | None = None
    dependencies_queried: int = 0


def _pinned_requirement(line: str) -> tuple[str, str] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", ".")) or "==" not in line:
        return None
    name, version = line.split("==", 1)
    name, version = name.strip(), version.strip()
    return (name, version) if name and version else None


def _requirements_dependencies(path: Path) -> list[Dependency]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    result: list[Dependency] = []
    for line in lines:
        item = _pinned_requirement(line)
        if item:
            result.append(Dependency(item[0], item[1], "PyPI", path.name))
    return result


def _package_lock_dependencies(path: Path) -> list[Dependency]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    found: dict[tuple[str, str], Dependency] = {}
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, package in packages.items():
            if not package_path.startswith("node_modules/") or not isinstance(package, dict):
                continue
            version = package.get("version")
            name = package_path.removeprefix("node_modules/")
            if isinstance(version, str) and name:
                found[(name, version)] = Dependency(name, version, "npm", path.name)
    if not found:
        def walk(items: dict[str, Any]) -> None:
            for name, item in items.items():
                if not isinstance(item, dict):
                    continue
                version = item.get("version")
                if isinstance(version, str):
                    found[(name, version)] = Dependency(name, version, "npm", path.name)
                children = item.get("dependencies")
                if isinstance(children, dict):
                    walk(children)
        if isinstance(payload.get("dependencies"), dict):
            walk(payload["dependencies"])
    return list(found.values())


def _package_json_dependencies(path: Path) -> list[Dependency]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    result: list[Dependency] = []
    for group in ("dependencies", "devDependencies"):
        for name, version in (payload.get(group) or {}).items():
            if isinstance(name, str) and isinstance(version, str) and _EXACT_VERSION.fullmatch(version):
                result.append(Dependency(name, version, "npm", path.name))
    return result


def _poetry_dependencies(path: Path) -> list[Dependency]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    packages = payload.get("package")
    if not isinstance(packages, list):
        return []
    return [Dependency(str(item["name"]), str(item["version"]), "PyPI", path.name) for item in packages if isinstance(item, dict) and item.get("name") and item.get("version")]


def _pipfile_lock_dependencies(path: Path) -> list[Dependency]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    result: list[Dependency] = []
    for group in ("default", "develop"):
        for name, details in (payload.get(group) or {}).items():
            version = details.get("version") if isinstance(details, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                result.append(Dependency(str(name), version[2:], "PyPI", path.name))
    return result


def discover_dependencies(repo_path: str | Path) -> list[Dependency]:
    root = validate_scan_path(repo_path)
    dependencies: dict[tuple[str, str, str], Dependency] = {}
    readers = (
        ("package-lock.json", _package_lock_dependencies),
        ("poetry.lock", _poetry_dependencies),
        ("Pipfile.lock", _pipfile_lock_dependencies),
        ("requirements.txt", _requirements_dependencies),
        ("package.json", _package_json_dependencies),
    )
    for filename, reader in readers:
        path = root / filename
        if path.exists():
            for dependency in reader(path):
                dependencies.setdefault((dependency.name, dependency.version, dependency.ecosystem), dependency)
    return list(dependencies.values())


def _severity(vulnerability: dict[str, Any]) -> str | None:
    database_specific = vulnerability.get("database_specific")
    if not isinstance(database_specific, dict):
        database_specific = {}
    for source in (database_specific, vulnerability):
        database_severity = source.get("severity") or source.get("database_severity")
        if isinstance(database_severity, str) and database_severity.lower() in {"critical", "high", "medium", "low"}:
            return database_severity.lower()

    score = _cvss_score(vulnerability)
    if score is not None:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return None


def _cvss_score(vulnerability: dict[str, Any]) -> float | None:
    database_specific = vulnerability.get("database_specific")
    candidates = [vulnerability.get("cvss_score")]
    if isinstance(database_specific, dict):
        candidates.append(database_specific.get("cvss_score"))
    for item in vulnerability.get("severity") or []:
        if isinstance(item, dict):
            candidates.extend((item.get("cvss_score"), item.get("base_score"), item.get("score")))
    for candidate in candidates:
        if isinstance(candidate, bool) or not isinstance(candidate, (int, float, str)):
            continue
        try:
            score = float(candidate)
        except ValueError:
            continue
        if 0 <= score <= 10:
            return score
    return None


def _matching_affected(vulnerability: dict[str, Any], dependency: Dependency) -> list[dict[str, Any]]:
    matching = []
    for affected in vulnerability.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(package, dict) or package.get("name") != dependency.name or package.get("ecosystem") != dependency.ecosystem:
            continue
        matching.append(affected)
    return matching


def _fixed_version(vulnerability: dict[str, Any], dependency: Dependency) -> str | None:
    for affected in _matching_affected(vulnerability, dependency):
        for range_ in affected.get("ranges") or []:
            for event in range_.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    return event["fixed"]
    return None


def _affected_version_range(vulnerability: dict[str, Any], dependency: Dependency) -> str | None:
    ranges: list[str] = []
    for affected in _matching_affected(vulnerability, dependency):
        versions = affected.get("versions")
        if isinstance(versions, list) and versions and not affected.get("ranges"):
            ranges.extend(str(version) for version in versions if isinstance(version, str))
        for range_ in affected.get("ranges") or []:
            events = range_.get("events") if isinstance(range_, dict) else None
            if not isinstance(events, list):
                continue
            introduced: str | None = None
            for event in events:
                if not isinstance(event, dict):
                    continue
                if isinstance(event.get("introduced"), str):
                    introduced = event["introduced"]
                for boundary in ("fixed", "last_affected"):
                    upper = event.get(boundary)
                    if not isinstance(upper, str):
                        continue
                    bounds = []
                    if introduced and introduced != "0":
                        bounds.append(f">= {introduced}")
                    bounds.append(f"{'<' if boundary == 'fixed' else '<='} {upper}")
                    ranges.append(", ".join(bounds))
                    introduced = None
            if introduced:
                ranges.append(f">= {introduced}" if introduced != "0" else "All versions")
    return " or ".join(dict.fromkeys(ranges)) or None


def _finding(vulnerability: dict[str, Any], dependency: Dependency) -> dict[str, Any] | None:
    identifier = vulnerability.get("id")
    if not isinstance(identifier, str) or not identifier:
        return None
    references = [item.get("url") for item in vulnerability.get("references") or [] if isinstance(item, dict) and isinstance(item.get("url"), str)]
    aliases = [alias for alias in vulnerability.get("aliases") or [] if isinstance(alias, str)]
    return {
        "type": "dependency", "scanner": "osv", "file": dependency.manifest, "line": None,
        "description": vulnerability.get("summary") or vulnerability.get("details") or identifier,
        "rule_id": identifier, "advisory_id": identifier, "aliases": aliases,
        "severity": _severity(vulnerability), "cvss_score": _cvss_score(vulnerability),
        "package": dependency.name, "ecosystem": dependency.ecosystem,
        "installed_version": dependency.version,
        "affected_versions": _affected_version_range(vulnerability, dependency),
        "fixed_version": _fixed_version(vulnerability, dependency), "references": references,
    }


def _merge_osv_finding(primary: dict[str, Any], duplicate: dict[str, Any]) -> bool:
    """Merge alias records for one package/version without collapsing distinct advisories."""
    identifiers = {duplicate["rule_id"], *duplicate["aliases"]}
    primary["aliases"] = sorted((set(primary["aliases"]) | identifiers) - {primary["rule_id"]})
    primary["references"] = list(dict.fromkeys([*primary["references"], *duplicate["references"]]))
    fixed_conflict = primary["fixed_version"] != duplicate["fixed_version"]
    if fixed_conflict:
        primary["fixed_version"] = None
    ranges = list(dict.fromkeys(
        value for value in (primary["affected_versions"], duplicate["affected_versions"]) if value
    ))
    if ranges:
        primary["affected_versions"] = " or ".join(ranges)
    severity_rank = {None: 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if severity_rank[duplicate["severity"]] > severity_rank[primary["severity"]]:
        primary["severity"] = duplicate["severity"]
    scores = [score for score in (primary["cvss_score"], duplicate["cvss_score"]) if score is not None]
    primary["cvss_score"] = max(scores) if scores else None
    return fixed_conflict


def scan_dependencies_with_status(repo_path: str | Path) -> DependencyScanResult:
    dependencies = discover_dependencies(repo_path)
    if not dependencies:
        return DependencyScanResult([], "skipped", "no_supported_resolved_dependencies")
    queries = [{"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.version} for item in dependencies]
    try:
        response = httpx.post(OSV_QUERY_BATCH_URL, json={"queries": queries}, timeout=settings.osv_timeout_seconds)
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return DependencyScanResult([], "unavailable", "osv_timeout", len(dependencies))
    except httpx.HTTPStatusError as exc:
        return DependencyScanResult([], "unavailable", "osv_rate_limited" if exc.response.status_code == 429 else "osv_http_error", len(dependencies))
    except (httpx.HTTPError, ValueError, json.JSONDecodeError):
        return DependencyScanResult([], "unavailable", "osv_invalid_or_unavailable", len(dependencies))
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(dependencies):
        return DependencyScanResult([], "unavailable", "osv_invalid_response", len(dependencies))
    findings: list[dict[str, Any]] = []
    finding_indexes: dict[tuple[str, str, str, str], int] = {}
    conflicting_fixed_versions: set[int] = set()
    vulnerability_cache: dict[str, dict[str, Any]] = {}
    for dependency, result in zip(dependencies, results):
        if not isinstance(result, dict):
            return DependencyScanResult([], "unavailable", "osv_invalid_response", len(dependencies))
        for summary in result.get("vulns") or []:
            identifier = summary.get("id") if isinstance(summary, dict) else None
            if not isinstance(identifier, str) or not identifier:
                continue
            if identifier not in vulnerability_cache:
                try:
                    detail_response = httpx.get(
                        f"{OSV_VULNERABILITY_URL}/{quote(identifier, safe='')}",
                        timeout=settings.osv_timeout_seconds,
                    )
                    detail_response.raise_for_status()
                    vulnerability = detail_response.json()
                except httpx.TimeoutException:
                    return DependencyScanResult([], "unavailable", "osv_vulnerability_details_timeout", len(dependencies))
                except httpx.HTTPStatusError:
                    return DependencyScanResult([], "unavailable", "osv_vulnerability_details_http_error", len(dependencies))
                except (httpx.HTTPError, ValueError, json.JSONDecodeError):
                    return DependencyScanResult([], "unavailable", "osv_vulnerability_details_invalid", len(dependencies))
                if not isinstance(vulnerability, dict) or vulnerability.get("id") != identifier:
                    return DependencyScanResult([], "unavailable", "osv_vulnerability_details_invalid", len(dependencies))
                vulnerability_cache[identifier] = vulnerability
            normalized = _finding(vulnerability_cache[identifier], dependency)
            if normalized:
                identifiers = {normalized["rule_id"], *normalized["aliases"]}
                scope = (dependency.name, dependency.version, dependency.ecosystem)
                matching_indexes = {
                    finding_indexes[(*scope, item)]
                    for item in identifiers
                    if (*scope, item) in finding_indexes
                }
                if not matching_indexes:
                    normalized["aliases"] = sorted(set(normalized["aliases"]) - {normalized["rule_id"]})
                    finding_index = len(findings)
                    findings.append(normalized)
                else:
                    finding_index = min(matching_indexes)
                    for duplicate_index in sorted(matching_indexes - {finding_index}, reverse=True):
                        if _merge_osv_finding(findings[finding_index], findings[duplicate_index]):
                            conflicting_fixed_versions.add(finding_index)
                        if duplicate_index in conflicting_fixed_versions:
                            conflicting_fixed_versions.add(finding_index)
                        findings.pop(duplicate_index)
                        conflicting_fixed_versions.discard(duplicate_index)
                        conflicting_fixed_versions = {
                            index - 1 if index > duplicate_index else index
                            for index in conflicting_fixed_versions
                        }
                        for key, index in tuple(finding_indexes.items()):
                            if index == duplicate_index:
                                finding_indexes[key] = finding_index
                            elif index > duplicate_index:
                                finding_indexes[key] = index - 1
                    if _merge_osv_finding(findings[finding_index], normalized):
                        conflicting_fixed_versions.add(finding_index)
                    if finding_index in conflicting_fixed_versions:
                        findings[finding_index]["fixed_version"] = None
                for item in identifiers:
                    finding_indexes[(*scope, item)] = finding_index
    return DependencyScanResult(findings, "completed" if findings else "empty", None, len(dependencies))


def scan_dependencies(repo_path: str) -> list[dict]:
    """Database scan compatibility entry point."""
    findings = scan_dependencies_with_status(repo_path).findings
    return [{
        "type": "dependency", "rule_id": item["rule_id"], "title": item["description"],
        "scanner": item["scanner"], "severity": item["severity"], "file_path": item["file"], "line": item["line"],
        "commit_sha": None, "secret_masked": None, "secret_hash": None, "package": item["package"],
        "ecosystem": item["ecosystem"], "installed_version": item["installed_version"], "affected_versions": item["affected_versions"],
        "fixed_version": item["fixed_version"], "advisory_id": item["advisory_id"], "aliases": item["aliases"],
        "references": item["references"], "cvss_score": item["cvss_score"], "in_history_only": False, "confidence": 0.9, "status": "open",
    } for item in findings]
