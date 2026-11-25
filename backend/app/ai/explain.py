from __future__ import annotations


def explain_finding(finding: dict) -> dict:
    """Provider-independent safe fallback explanation; it only sees the masked finding."""
    is_secret = finding["type"] == "secret"
    return {
        "what": f"{finding['title']} was detected in {finding.get('file_path') or 'the repository'}.",
        "why_dangerous": "A committed credential can be copied from repository history and used without authorization." if is_secret else "A vulnerable dependency can expose the application to known security issues.",
        "how_fixed": "Move the value to an environment variable and remove it from the current source file." if is_secret else f"Upgrade {finding.get('package')} to {finding.get('fixed_version') or 'a patched version'}.",
        "rotation_required": is_secret,
        "rotation_note": "This secret remains in git history. Revoke and rotate the credential before merging." if is_secret else "No credential rotation is required for a dependency finding.",
    }
