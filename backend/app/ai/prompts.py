"""Prompts for the AI fix agent.

The LLM does ONE job: rewrite the affected file so the secret is read from an
environment variable. Everything else (.env.example, .gitignore, rotation note,
tier, validation) is done by our own code, because code is predictable and the
LLM is not.
"""
import json

from app.ai.redact import REDACTION_TOKEN

LANGUAGE_RULES = {
    "python": 'Read the value with os.getenv("NAME"). Add "import os" at the top if it is missing.',
    "node": "Read the value with process.env.NAME.",
}

SYSTEM_PROMPT = f"""You are a senior security engineer fixing a hardcoded secret in source code.

The secret has already been removed from the file and replaced with the token {REDACTION_TOKEN}.
Your job: rewrite the file so that value is read from an environment variable instead.

RULES
1. Choose a clear UPPER_SNAKE_CASE environment variable name that describes the secret
   (for example AWS_ACCESS_KEY_ID, STRIPE_SECRET_KEY, GITHUB_TOKEN).
2. Replace the token (and the quotes around it) with a read of that environment variable.
   The token can appear MORE THAN ONCE, including inside a larger string such as a database URL.
   Every occurrence must read the SAME environment variable (e.g. build the URL with an f-string).
3. Change ONLY what is needed for the fix. Keep every other line exactly as it is:
   same order, same indentation, same comments, same blank lines.
3b. Placeholders like <<OTHER_SECRET_1>> are OTHER secrets that are fixed separately.
   Leave every one of them exactly as it is, in the same place. Do not rename, move or remove them.
4. Never write {REDACTION_TOKEN}, a placeholder secret, or a default value for the secret.
5. Do not add new libraries (no python-dotenv, no dotenv package).
6. Return the COMPLETE new file in "new_content", not a diff and not a snippet.

Reply with ONLY one JSON object in exactly this shape:
{{
  "env_var_name": "UPPER_SNAKE_CASE_NAME",
  "explanation": {{
    "what": "one sentence: what was found and where",
    "why_dangerous": "one or two sentences a junior developer understands",
    "how_fixed": "one sentence: what you changed"
  }},
  "new_content": "the complete new file content"
}}
"""

EXAMPLE_INPUT = f'''import boto3

AWS_ACCESS_KEY_ID = "{REDACTION_TOKEN}"
s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
'''

EXAMPLE_OUTPUT = {
    "env_var_name": "AWS_ACCESS_KEY_ID",
    "explanation": {
        "what": "An AWS access key was hardcoded in config.py on line 3.",
        "why_dangerous": "Anyone who can read this repository or its history can use the key to access the AWS account.",
        "how_fixed": "The key is now read from the AWS_ACCESS_KEY_ID environment variable.",
    },
    "new_content": 'import os\n\nimport boto3\n\nAWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")\n'
                   's3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)\n',
}


def build_user_prompt(finding: dict, redacted_content: str, language: str, repo_files: list[str]) -> str:
    """The task for one finding. redacted_content must already have the secret replaced."""
    other_files = ", ".join(repo_files[:50]) or "(not provided)"
    return f"""EXAMPLE
Input file (python):
{EXAMPLE_INPUT}
Correct reply:
{json.dumps(EXAMPLE_OUTPUT, indent=2)}

YOUR TASK
Finding: {finding.get("title")} (rule: {finding.get("rule_id")})
File: {finding.get("file_path")}, line {finding.get("line")}
Language: {language}. {LANGUAGE_RULES[language]}
Other files in the repository: {other_files}

File content:
{redacted_content}"""

# ---------------------------------------------------------------------------
# Self-healing agent: repair a fix that broke the repository's own CI.
# ---------------------------------------------------------------------------

LOG_REDACTION_TOKEN = "<<REDACTED_IN_LOG>>"

REPAIR_SYSTEM_PROMPT = f"""You are a senior engineer repairing a security fix that broke the project's CI.

Earlier, a hardcoded secret in this file was replaced with a read of an environment variable.
After that change the repository's own CI failed. You get the CURRENT file (with the fix)
and the error lines from the CI log. Make the SMALLEST change to THIS file that makes CI pass.

RULES
1. The secret must stay out of the code. Keep reading it from the environment variable.
   Never write a credential, a fake credential or a default secret value.
2. Typical causes: a missing import (e.g. "import os"), os.environ["X"] raising KeyError in
   CI where the variable is not set (use os.getenv("X") instead), a typo in a name.
3. Change ONLY what is needed. Keep every other line exactly as it is.
4. Placeholders like <<OTHER_SECRET_1>> are other secrets handled separately: leave them as they are.
   {LOG_REDACTION_TOKEN} in the log means something was hidden from you; ignore it.
5. If the CI errors are NOT caused by this file (e.g. a test that was already failing, a missing
   package, a network error), do not guess: set "fixable" to false and explain why in "cause".
6. Return the COMPLETE new file in "new_content" (or "" when fixable is false).

Reply with ONLY one JSON object in exactly this shape:
{{
  "fixable": true,
  "cause": "one sentence: why CI failed",
  "how_fixed": "one sentence: what you changed",
  "new_content": "the complete new file content"
}}
"""


def build_repair_prompt(finding: dict, content: str, language: str, ci_errors: list[str]) -> str:
    """content and ci_errors must already have every secret hidden."""
    errors = "\n".join(ci_errors) or "(no error lines found)"
    return f"""Original finding: {finding.get("title")} (rule: {finding.get("rule_id")})
File: {finding.get("file_path")}
Language: {language}. {LANGUAGE_RULES[language]}

CI error lines:
{errors}

Current file content:
{content}"""