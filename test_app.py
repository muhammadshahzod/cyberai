"""Basic tests for the CyberCheck backend.

    pip install pytest
    pytest -q
"""

import ai_extencion as app_mod
from ai_extencion import app


def _post(client, body, headers=None):
    return client.post("/api/check", json=body, headers=headers or {})


def test_health():
    client = app.test_client()
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_bad_type():
    client = app.test_client()
    r = _post(client, {"type": "nope", "value": "x"})
    assert r.status_code == 400


def test_empty_value():
    client = app.test_client()
    r = _post(client, {"type": "url", "value": "   "})
    assert r.status_code == 400


def test_password_weak():
    client = app.test_client()
    r = _post(client, {"type": "password", "value": "123456"})
    assert r.status_code == 200
    j = r.get_json()
    assert j["risk_level"] == "high"
    assert "check_password_strength" in j["checks"]
    assert isinstance(j["signals"], list)


def test_url_bare_domain_is_low():
    app_mod.new_collection()
    f = app_mod._check_phishing_impl("google.com")
    assert f["severity"] == "low"
    assert f["details"]["heuristic_score"] == 0


def test_url_explicit_http_penalised():
    app_mod.new_collection()
    f = app_mod._check_phishing_impl("http://google.com")
    assert f["severity"] == "medium"


def test_url_typosquat_flagged():
    app_mod.new_collection()
    f = app_mod._check_phishing_impl("https://g00gle.com")
    assert f["details"]["possible_typosquat_of"] == "google.com"
    assert f["severity"] in ("medium", "high")


def test_url_ip_and_http_is_high():
    app_mod.new_collection()
    f = app_mod._check_phishing_impl("http://192.168.10.5/login")
    assert f["severity"] == "high"
    assert f["details"]["is_ip_literal"] is True


def test_breach_sends_only_prefix():
    app_mod.new_collection()
    f = app_mod._check_breach_impl("hunter2")
    assert f["details"]["bytes_of_raw_value_sent"] == 0
    assert len(f["details"]["sha1_prefix_sent"]) == 5


def test_cache_returns_same_payload():
    client = app.test_client()
    b = {"type": "url", "value": "https://example-cache-test.com"}
    r1 = _post(client, b).get_json()
    r2 = _post(client, b).get_json()
    assert r2["cached"] is True
    assert r1["risk_level"] == r2["risk_level"]


def test_api_key_enforced(monkeypatch):
    monkeypatch.setattr(app_mod, "API_KEY", "secret123")
    client = app.test_client()
    assert _post(client, {"type": "password", "value": "x"}).status_code == 401
    ok = _post(client, {"type": "password", "value": "x"}, headers={"X-API-Key": "secret123"})
    assert ok.status_code == 200
