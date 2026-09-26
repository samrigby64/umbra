from umbra.config import Settings


def test_focus_keywords_accepts_comma_separated_env(monkeypatch):
    # The documented human-friendly form must not crash Settings() at startup.
    monkeypatch.setenv("UMBRA_FOCUS_KEYWORDS", "drugs, weapons ,leak")
    assert Settings().focus_keywords == ["drugs", "weapons", "leak"]


def test_focus_keywords_accepts_json_env(monkeypatch):
    monkeypatch.setenv("UMBRA_FOCUS_KEYWORDS", '["a","b"]')
    assert Settings().focus_keywords == ["a", "b"]


def test_focus_keywords_default_empty():
    assert Settings().focus_keywords == []
