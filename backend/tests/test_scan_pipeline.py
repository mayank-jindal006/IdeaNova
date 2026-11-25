import json

import pytest

from app.ai.models import Finding
from app.ai.redaction import redact_context_for_llm, redact_source_line, redact_content_for_llm
from app.services.gitleaks import parse_gitleaks_report
from app.services.ai_service import build_security_prompt


def test_finding_aliases_preserve_column_metadata():
    finding = Finding.model_validate({
        "file": "src/config.js",
        "StartLine": 12,
        "EndLine": 12,
        "StartColumn": 18,
        "EndColumn": 32,
        "Secret": "AKIA1234567890EXAMPLE",
        "rule_id": "aws-access-token",
        "severity": "critical",
    })

    assert finding.start_line == 12
    assert finding.end_line == 12
    assert finding.start_column == 18
    assert finding.end_column == 32


def test_redaction_masks_secret_using_exact_column_range():
    finding = Finding(
        file="src/config.js",
        start_line=2,
        end_line=2,
        start_column=13,
        end_column=31,
        secret="ghp_1234567890",
        match="ghp_1234567890",
    )
    source_line = "const token = 'ghp_1234567890';"

    redacted = finding.redact_source_line(source_line)

    assert "ghp_1234567890" not in redacted
    assert "[REDACTED]" in redacted
    assert redacted.count("[REDACTED]") == 1


def test_parse_gitleaks_report_preserves_coordinates():
    payload = {
        "Findings": [
            {
                "Description": "AWS Access Token",
                "StartLine": 8,
                "EndLine": 8,
                "StartColumn": 15,
                "EndColumn": 40,
                "Secret": "AKIA1234567890EXAMPLE",
                "Match": "AKIA1234567890EXAMPLE",
                "RuleID": "aws-access-token",
                "Severity": "critical",
                "File": "src/config.js",
            }
        ]
    }

    findings = parse_gitleaks_report(json.dumps(payload))

    assert len(findings) == 1
    result = findings[0]
    assert result.file == "src/config.js"
    assert result.start_line == 8
    assert result.end_line == 8
    assert result.start_column == 15
    assert result.end_column == 40
    assert result.secret == "AKIA1234567890EXAMPLE"


def test_redact_content_for_llm_removes_secrets_before_prompting():
    content = "const token = 'ghp_1234567890';\nconst apiKey = 'super-secret';"
    sanitized = redact_content_for_llm(content, ["ghp_1234567890", "super-secret"])

    assert "ghp_1234567890" not in sanitized
    assert "super-secret" not in sanitized
    assert "[REDACTED]" in sanitized


def test_redact_context_for_llm_catches_second_unrelated_secret():
    context = "primary = 'ghp_1234567890';\npassword=AnotherSecretValue123"
    sanitized = redact_context_for_llm(context, ["ghp_1234567890"])

    assert "ghp_1234567890" not in sanitized
    assert "AnotherSecretValue123" not in sanitized
    assert sanitized.count("[REDACTED]") >= 2


def test_build_security_prompt_mentions_risk_and_remediation():
    finding = Finding(
        file="src/config.js",
        line=8,
        rule_id="aws-access-token",
        description="AWS Access Token",
        severity="critical",
        secret="AKIA1234567890EXAMPLE",
        start_line=8,
        end_line=8,
        start_column=15,
        end_column=40,
    )

    prompt = build_security_prompt(finding, "const apiKey = process.env.API_KEY;")

    assert "Security finding" in prompt
    assert "risk" in prompt.lower()
    assert "remediation" in prompt.lower()
    assert "AKIA1234567890EXAMPLE" not in prompt
