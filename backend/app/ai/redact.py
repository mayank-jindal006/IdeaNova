"""Hide a secret inside file content before the file is sent to the LLM.

The real secret must NEVER leave our system. We replace it with a fixed token,
so the LLM still sees *where* the secret was and can rewrite that code.
"""

REDACTION_TOKEN = "<<REDACTED_SECRET>>"


def extract_secret(file_content: str, finding: dict) -> str | None:
    """Return the exact secret text at the finding's position, or None if we can't be sure.

    Safety check: the text at line/start_column/end_column must match secret_masked
    (first 4 and last 4 characters). If it doesn't, the columns are wrong -> None.
    """
    line_no = finding.get("line")
    start = finding.get("start_column")   # 1-based, first char of the secret
    end = finding.get("end_column")       # 1-based, last char of the secret (inclusive)
    masked = finding.get("secret_masked") or ""

    if not line_no or not start or not end or end < start:
        return None
    lines = file_content.splitlines(keepends=True)   # keepends: don't lose \n or \r\n
    if line_no < 1 or line_no > len(lines):
        return None

    secret = lines[line_no - 1][start - 1:end]
    if len(masked) < 8 or "****" not in masked:
        return None
    if len(secret) < 8 or secret[:4] != masked[:4] or secret[-4:] != masked[-4:]:
        return None
    return secret


def redact(file_content: str, finding: dict) -> str | None:
    """Return file_content with EVERY copy of the finding's secret replaced by REDACTION_TOKEN.

    Every copy, not just the reported one: the same password often appears twice
    (e.g. DB_PASSWORD = "..." and inside DATABASE_URL), and no copy may reach the LLM.
    Returns None if the secret's position can't be confirmed; the caller must then
    NOT send the file to the LLM.
    """
    secret = extract_secret(file_content, finding)
    if secret is None:
        return None
    return file_content.replace(secret, REDACTION_TOKEN)


OTHER_TOKEN = "<<OTHER_SECRET_{n}>>"


def hide_other_secrets(content: str, others: list[str]) -> tuple[str, dict[str, str]]:
    """Replace OTHER secrets in the file (separate findings) with numbered placeholders.

    The LLM must leave these untouched; restore_other_secrets() puts the real values back
    afterwards, so this fix only changes the one secret it is about.
    Returns (content, {placeholder: original_value}). Longest values first, so a secret that
    contains another one is replaced whole.
    """
    mapping: dict[str, str] = {}
    for value in sorted(set(others), key=len, reverse=True):
        if value and value in content:
            placeholder = OTHER_TOKEN.format(n=len(mapping) + 1)
            content = content.replace(value, placeholder)
            mapping[placeholder] = value
    return content, mapping


def restore_other_secrets(content: str, mapping: dict[str, str]) -> str:
    for placeholder, value in mapping.items():
        content = content.replace(placeholder, value)
    return content