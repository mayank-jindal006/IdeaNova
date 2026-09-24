"""Hide a secret inside file content before the file is sent to the LLM.

The real secret must NEVER leave our system. We replace it with a fixed token,
so the LLM still sees *where* the secret was and can rewrite that line.
"""

REDACTION_TOKEN = "<<REDACTED_SECRET>>"


def redact(file_content: str, finding: dict) -> str | None:
    """Return file_content with the finding's secret replaced by REDACTION_TOKEN.

    Returns None if we can't be sure we found the exact secret. The caller must
    then NOT send the file to the LLM (the finding becomes flag_only).
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

    line = lines[line_no - 1]
    secret = line[start - 1:end]

    # Safety check: the text we are about to hide must match the masked secret
    # (first 4 and last 4 characters). If not, the columns are wrong -> refuse.
    if len(masked) < 8 or "****" not in masked:
        return None
    if len(secret) < 8 or secret[:4] != masked[:4] or secret[-4:] != masked[-4:]:
        return None

    lines[line_no - 1] = line[:start - 1] + REDACTION_TOKEN + line[end:]
    return "".join(lines)