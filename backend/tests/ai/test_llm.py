"""Unit tests for llm.py. They use a FAKE LLM, so they're free, fast, and need no internet."""
from app.ai import llm


def test_plain_json():
    assert llm.extract_json('{"a": 1}') == {"a": 1}


def test_fenced_json():
    assert llm.extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_json_with_extra_text():
    assert llm.extract_json('Sure! Here it is: {"a": 1} Hope this helps') == {"a": 1}


def test_retries_when_reply_is_not_json(monkeypatch):
    replies = iter(["this is not json", '{"ok": true}'])
    monkeypatch.setattr(llm, "API_KEY", "fake")
    monkeypatch.setattr(llm, "MODEL", "fake")
    monkeypatch.setattr(llm, "PROVIDER", "fake")
    monkeypatch.setitem(llm._CALLERS, "fake", lambda system, user: next(replies))
    assert llm.complete_json("sys", "user") == {"ok": True}