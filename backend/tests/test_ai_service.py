import logging
from unittest.mock import patch

from app.ai.llm import LLMError
from app.ai.models import Finding
from app.services.ai_service import build_security_prompt, generate_security_recommendation


def _finding() -> Finding:
    return Finding(
        file="src/config.py",
        line=8,
        rule_id="github-pat",
        description="GitHub token detected",
        severity="critical",
        secret="ghp_1234567890",
        match="ghp_1234567890",
    )


def _dependency_finding(*, fixed_version: str | None = "1.2.2") -> Finding:
    return Finding(
        type="dependency",
        scanner="osv",
        file="package-lock.json",
        rule_id="GHSA-test-1234",
        advisory_id="GHSA-test-1234",
        description="Test package vulnerability",
        severity="high",
        package="source-map-js",
        ecosystem="npm",
        installed_version="1.2.1",
        affected_versions=">= 1.0.0, < 1.2.2",
        fixed_version=fixed_version,
        aliases=["CVE-2026-12345"],
        references=["https://example.invalid/advisory"],
    )


def _model_response() -> dict:
    return {
        "summary": "A GitHub token was detected in source code.",
        "risk_assessment": "An attacker could use it to access repositories.",
        "remediation": "Revoke it and move replacement credentials to a secret manager.",
        "developer_summary": "Add secret scanning to pre-commit checks.",
        "requires_rotation": True,
        "confidence": 0.88,
    }


def test_gemini_response_is_marked_and_normalized_without_secret():
    finding = _finding()
    with patch("app.services.ai_service.complete_json", return_value=_model_response()) as complete:
        result = generate_security_recommendation(finding, "token = 'ghp_1234567890'")

    assert complete.call_count == 1
    assert result["guidance_source"] == "gemini"
    assert result["summary"] == _model_response()["summary"]
    prompt = complete.call_args.kwargs["user"]
    assert "ghp_1234567890" not in prompt
    assert "[REDACTED]" in prompt


def test_provider_error_returns_labeled_rule_based_fallback():
    finding = _finding()
    with patch("app.services.ai_service.complete_json", side_effect=LLMError("provider unavailable", category="timeout")):
        result = generate_security_recommendation(finding, "")

    assert result["guidance_source"] == "rule_based_fallback"
    assert result["guidance_failure_reason"] == "timeout"
    assert result["requires_rotation"] is True


def test_provider_error_does_not_log_untrusted_finding_metadata(caplog):
    marker = "synthetic-sensitive-rule-value"
    finding = _finding().model_copy(update={"rule_id": marker})
    with patch(
        "app.services.ai_service.complete_json",
        side_effect=LLMError("provider unavailable", category="timeout"),
    ), caplog.at_level(logging.WARNING, logger="app.services.ai_service"):
        generate_security_recommendation(finding, "")

    assert marker not in caplog.text


def test_invalid_model_response_returns_labeled_rule_based_fallback():
    finding = _finding()
    with patch("app.services.ai_service.complete_json", return_value={"summary": "partial response"}):
        result = generate_security_recommendation(finding, "")

    assert result["guidance_source"] == "rule_based_fallback"
    assert result["guidance_failure_reason"] == "malformed_response"


def test_dependency_guidance_uses_verified_metadata_and_never_requests_rotation():
    finding = _dependency_finding()
    prompt = build_security_prompt(finding, "")
    with patch(
        "app.services.ai_service.complete_json",
        side_effect=LLMError("provider unavailable", category="timeout"),
    ):
        result = generate_security_recommendation(finding, "")

    assert "source-map-js" in prompt
    assert "1.2.1" in prompt
    assert "GHSA-test-1234" in prompt
    assert ">= 1.0.0, < 1.2.2" in prompt
    assert "1.2.2" in prompt
    assert "Do not recommend credential rotation" in prompt
    assert result["requires_rotation"] is False
    assert "1.2.2" in result["remediation"]
    assert "source-map-js" in result["summary"]
    assert "credential" not in result["remediation"].lower()


def test_dependency_guidance_does_not_invent_missing_fixed_version():
    finding = _dependency_finding(fixed_version=None)
    with patch(
        "app.services.ai_service.complete_json",
        side_effect=LLMError("provider unavailable", category="timeout"),
    ):
        result = generate_security_recommendation(finding, "")
    prompt = build_security_prompt(finding, "")

    assert '"fixed_version"' not in prompt
    assert "Do not invent a patched version" in prompt
    assert "no fixed version is available" in result["remediation"].lower()
    assert "1.2.2" not in result["remediation"]
    assert result["requires_rotation"] is False


def test_dependency_gemini_cannot_replace_verified_upgrade_with_unverified_version():
    finding = _dependency_finding()
    response = _model_response() | {
        "summary": "Package risk summary.",
        "risk_assessment": "Assess whether the affected functionality is reachable.",
        "remediation": "Upgrade to version 9.9.9.",
        "developer_summary": "Install version 9.9.9.",
        "requires_rotation": True,
    }
    with patch("app.services.ai_service.complete_json", return_value=response):
        result = generate_security_recommendation(finding, "")

    assert result["guidance_source"] == "gemini"
    assert "1.2.2" in result["remediation"]
    assert "9.9.9" not in str(result)
    assert result["requires_rotation"] is False


def test_secret_fallback_guidance_still_requires_rotation_for_critical_secret():
    with patch(
        "app.services.ai_service.complete_json",
        side_effect=LLMError("provider unavailable", category="timeout"),
    ):
        result = generate_security_recommendation(_finding(), "")

    assert result["requires_rotation"] is True
    assert "rotate the credential" in result["remediation"]
    assert "hardcoded credential" in result["developer_summary"]
