"""Basic tests for the CyberUzCheck backend.

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


def test_email_headers_spoof_detected():
    app_mod.new_collection()
    raw = (
        "From: PayPal <help@paypa1-security.ru>\n"
        "Return-Path: <x@sketchy.tk>\n"
        "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n"
        "Received: from a\n"
    )
    f = app_mod._check_email_headers_impl(raw)
    assert f["severity"] == "high"
    assert f["details"]["dmarc"] == "fail"
    assert f["details"]["from_domain"] == "paypa1-security.ru"


def test_headers_type_via_endpoint():
    client = app.test_client()
    r = _post(client, {"type": "headers", "value": "From: a@b.com\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\nReceived: x"})
    assert r.status_code == 200
    assert "check_email_headers" in r.get_json()["checks"]


def test_file_hash_invalid():
    app_mod.new_collection()
    f = app_mod._check_file_hash_impl("not-a-hash")
    assert f["severity"] == "medium"


def test_file_hash_without_key_is_unknown(monkeypatch):
    monkeypatch.setattr(app_mod, "VT_API_KEY", "")
    app_mod.new_collection()
    f = app_mod._check_file_hash_impl("d41d8cd98f00b204e9800998ecf8427e")
    assert f["severity"] == "unknown"


def test_stats_json():
    client = app.test_client()
    r = client.get("/stats?format=json")
    assert r.status_code == 200
    assert "checks_total" in r.get_json()


def test_feedback_accepts():
    client = app.test_client()
    r = client.post("/api/feedback", json={"host": "x.com", "correct": False, "note": "t"})
    assert r.status_code == 200 and r.get_json()["ok"] is True
