"""Unit tests for llm.py. They use FAKE providers, so they're free, fast, and need no internet."""
import pytest

from app.ai import llm


@pytest.fixture
def providers(monkeypatch):
    """Configure a fake main provider (and optionally a fake fallback) through env vars.

    main / fallback: a function(cfg, system, user) -> str, or None for "not configured".
    Returns a list that records which provider was called, in order.
    """
    calls = []
    monkeypatch.setattr(llm.time, "sleep", lambda seconds: None)   # no real waiting in tests
    for name in ("PROVIDER", "MODEL", "API_KEY", "BASE_URL"):
        monkeypatch.delenv(f"LLM_{name}", raising=False)
        monkeypatch.delenv(f"LLM_FALLBACK_{name}", raising=False)

    def install(main, fallback=None, main_key="key"):
        for prefix, fn, key in (("LLM_", main, main_key), ("LLM_FALLBACK_", fallback, "key")):
            if fn is None:
                continue
            name = "fake_main" if prefix == "LLM_" else "fake_fallback"

            def recorded(cfg, system, user, fn=fn, name=name):
                calls.append(name)
                return fn(cfg, system, user)

            monkeypatch.setitem(llm._CALLERS, name, recorded)
            monkeypatch.setenv(f"{prefix}PROVIDER", name)
            monkeypatch.setenv(f"{prefix}MODEL", "fake-model")
            if key:
                monkeypatch.setenv(f"{prefix}API_KEY", key)
        return calls
    return install


def down(cfg, system, user):
    raise ConnectionError("503 Service Unavailable")


def ok(cfg, system, user):
    return '{"ok": true}'


# ---------- extract_json ----------

def test_plain_json():
    assert llm.extract_json('{"a": 1}') == {"a": 1}


def test_fenced_json():
    assert llm.extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_json_with_extra_text():
    assert llm.extract_json('Sure! Here it is: {"a": 1} Hope this helps') == {"a": 1}


# ---------- retries on one provider ----------

def test_retries_when_reply_is_not_json(providers):
    replies = iter(["this is not json", '{"ok": true}'])
    calls = providers(lambda cfg, s, u: next(replies))
    assert llm.complete_json("sys", "user") == {"ok": True}
    assert calls == ["fake_main", "fake_main"]


# ---------- fallback ----------

def test_fallback_not_used_when_main_works(providers):
    calls = providers(ok, fallback=ok)
    assert llm.complete_json("sys", "user") == {"ok": True}
    assert calls == ["fake_main"]


def test_fallback_used_when_main_is_down(providers):
    calls = providers(down, fallback=ok)
    assert llm.complete_json("sys", "user") == {"ok": True}
    assert calls == ["fake_main", "fake_main", "fake_fallback"]   # 1 try + 1 retry, then switch


def test_fallback_used_when_main_key_is_missing(providers):
    calls = providers(ok, fallback=ok, main_key=None)
    assert llm.complete_json("sys", "user") == {"ok": True}
    assert calls == ["fake_fallback"]


def test_both_down_raises_with_both_reasons(providers):
    providers(down, fallback=down)
    with pytest.raises(llm.LLMError) as err:
        llm.complete_json("sys", "user")
    assert "main provider" in str(err.value)
    assert "fallback provider" in str(err.value)


def test_no_fallback_configured_uses_full_retries(providers):
    calls = providers(down)
    with pytest.raises(llm.LLMError):
        llm.complete_json("sys", "user")
    assert calls == ["fake_main"] * 3


def test_nothing_configured_raises(providers):
    with pytest.raises(llm.LLMError):
        llm.complete_json("sys", "user")


def test_fallback_without_key_is_ignored(providers, monkeypatch):
    calls = providers(down, fallback=ok)
    monkeypatch.delenv("LLM_FALLBACK_API_KEY")
    with pytest.raises(llm.LLMError):
        llm.complete_json("sys", "user")
    assert calls == ["fake_main"] * 3          # full retries on main, fallback never tried