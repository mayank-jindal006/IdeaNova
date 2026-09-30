CHECKLISTS = {
    "aws": {"provider": "AWS", "steps": [
        "Open AWS IAM and deactivate the exposed access key.",
        "Create a new access key and store it in a secrets manager or environment variable.",
        "Update every app and pipeline that used the old key.",
        "Check CloudTrail for any use of the old key.",
        "Delete the old key once nothing depends on it."]},
    "github": {"provider": "GitHub", "steps": [
        "Go to GitHub Settings, Developer settings, Personal access tokens, and revoke the token.",
        "Generate a new token with the minimum scopes needed.",
        "Store it in an environment variable or CI secret.",
        "Review the audit log for unexpected activity."]},
    "stripe": {"provider": "Stripe", "steps": [
        "Open the Stripe Dashboard, Developers, API keys, and roll the exposed key.",
        "Update the new key in your environment or secrets manager.",
        "Check recent API activity for suspicious requests."]},
    "database": {"provider": "Database", "steps": [
        "Change the database password immediately.",
        "Update the new password in your secrets manager or environment variable.",
        "Review connection and query logs for unknown access."]},
    "generic": {"provider": "Unknown", "steps": [
        "Identify which service this key belongs to.",
        "Revoke or regenerate it in that service.",
        "Store the new value in an environment variable or secrets manager.",
        "Check that service's logs for unexpected use."]},
}


def detect_secret_type(finding: dict) -> str:
    masked = finding.get("secret_masked") or ""
    rule = (finding.get("rule_id") or "").lower()
    title = (finding.get("title") or "").lower()
    filename = (finding.get("file_path") or "").lower().split("/")[-1]
    if masked.startswith("AKIA") or rule == "aws-access-token" or "aws" in title:
        return "aws"
    if masked.startswith(("ghp_", "github_pat_")) or "github" in rule or "github" in title:
        return "github"
    if masked.startswith(("sk_test_", "sk_live_")) or "stripe" in title:
        return "stripe"
    if "database" in title or "password" in title or filename.startswith("db"):
        return "database"
    return "generic"


def get_rotation_checklist(finding: dict):
    if finding.get("type") != "secret":
        return None
    key = detect_secret_type(finding)
    data = CHECKLISTS[key]
    return {
        "secret_type": key,
        "provider": data["provider"],
        "steps": list(data["steps"]),
        "note": "Fixing the code does not remove the secret from git history. Rotate this credential.",
    }