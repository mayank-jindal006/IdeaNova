"""Conservative local remediation for exact-pinned Python requirements."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")


def requirements_candidate(path: str, content: str, finding: dict) -> str | None:
    """Return the sole metadata-backed pin change, or decline ambiguous input."""
    if PurePosixPath(path).name != "requirements.txt" or finding.get("ecosystem") != "PyPI":
        return None
    package = finding.get("package")
    installed = finding.get("installed_version")
    fixed = finding.get("fixed_version")
    if not all(isinstance(value, str) and value for value in (package, installed, fixed)):
        return None
    try:
        if Version(fixed) <= Version(installed):
            return None
    except InvalidVersion:
        return None
    lines = content.splitlines(keepends=True)
    replacement = None
    for index, line in enumerate(lines):
        text = line.rstrip("\r\n")
        if not text:
            continue
        match = _PIN.fullmatch(text)
        if not match:
            return None
        try:
            Version(match.group(2))
        except InvalidVersion:
            return None
        if canonicalize_name(match.group(1)) == canonicalize_name(package):
            if replacement is not None or match.group(2) != installed:
                return None
            replacement = (index, match.group(1) + "==" + fixed + line[len(text):])
    if replacement is None:
        return None
    lines[replacement[0]] = replacement[1]
    return "".join(lines)
