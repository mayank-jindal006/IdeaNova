from dataclasses import replace
from unittest.mock import Mock, patch

import pytest

from app.ai.llm import GUIDANCE_RESPONSE_SCHEMA, LLMError, complete_json
from app.settings import load_settings, settings


def _configured_settings(**changes):
    values = {
        "llm_provider": "gemini",
        "llm_model": "gemini-test-model",
        "llm_api_key": "test-key",
    }
    values.update(changes)
    return replace(settings, **values)


def test_load_settings_reads_gemini_environment_names(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "GEMINI")
    monkeypatch.setenv("LLM_MODEL", "gemini-test-model")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_TIMEOUT", "12.5")

    configured = load_settings()

    assert configured.llm_provider == "gemini"
    assert configured.llm_model == "gemini-test-model"
    assert configured.llm_api_key == "test-key"
    assert configured.llm_timeout_seconds == 12.5


def test_complete_json_reports_missing_configuration_without_value():
    with patch("app.ai.llm.settings", _configured_settings(llm_api_key=None)):
        with pytest.raises(LLMError) as error:
            complete_json("system", "user", retries=0)

    assert error.value.category == "missing_configuration"
    assert "test-key" not in str(error.value)


def test_complete_json_classifies_provider_permission_failure():
    provider_error = type("ProviderError", (Exception,), {"status_code": 403})()
    with patch("app.ai.llm.settings", _configured_settings()):
        with patch.dict("app.ai.llm._CALLERS", {"gemini": Mock(side_effect=provider_error)}):
            with pytest.raises(LLMError) as error:
                complete_json("system", "user", retries=0)

    assert error.value.category == "authentication_or_permission"
    assert error.value.status_code == 403


def test_complete_json_rejects_malformed_provider_response():
    with patch("app.ai.llm.settings", _configured_settings()):
        with patch.dict("app.ai.llm._CALLERS", {"gemini": Mock(return_value="not json")}):
            with pytest.raises(LLMError) as error:
                complete_json("system", "user", retries=0)

    assert error.value.category == "malformed_response"


def test_complete_json_returns_valid_gemini_response():
    response = '{"summary":"Safe answer","risk_assessment":"Risk","remediation":"Fix","developer_summary":"Prevent","requires_rotation":true,"confidence":0.9}'
    caller = Mock(return_value=response)
    with patch("app.ai.llm.settings", _configured_settings()):
        with patch.dict("app.ai.llm._CALLERS", {"gemini": caller}):
            payload = complete_json("system", "user", retries=0)

    assert caller.call_count == 1
    assert payload["summary"] == "Safe answer"
    assert payload["requires_rotation"] is True


def test_gemini_guidance_schema_requires_every_contract_field():
    assert GUIDANCE_RESPONSE_SCHEMA["required"] == [
        "summary",
        "risk_assessment",
        "remediation",
        "developer_summary",
        "requires_rotation",
        "confidence",
    ]
    assert GUIDANCE_RESPONSE_SCHEMA["properties"]["requires_rotation"]["type"] == "boolean"
    assert GUIDANCE_RESPONSE_SCHEMA["properties"]["confidence"]["type"] == "number"
