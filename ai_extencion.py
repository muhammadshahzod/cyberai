"""CyberCheck - Personal Cybersecurity Checker Agent.

AWS "Agents for Humans" hackathon project. Single Strands agent + three security
tools, exposed over one Flask endpoint. Everything (backend + Chrome extension)
lives in this one folder.

Run:
    pip install -r requirements.txt
    python ai_extencion.py            # -> http://127.0.0.1:5000

Endpoint:
    POST /api/check   {"type": "email"|"url"|"password", "value": "<string>"}
    ->                {"risk_level": "low"|"medium"|"high", "summary": "...", "details": {...}}

Privacy:
    * check_breach            - only the first 5 chars of SHA-1(value) ever leave
                               the process (k-anonymity). Raw value never sent.
    * check_password_strength - raw password is never logged, stored, or echoed.
    * the backend never logs the `value` field.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

try:  # Strands is optional at import time; missing/unconfigured -> direct mode
    from strands import Agent, tool
except Exception:  # pragma: no cover
    Agent = None

    def tool(func=None, **_kwargs):
        if func is None:
            return lambda f: f
        return func


# ========================================================================== #
# Per-request findings collector
# ========================================================================== #
_state = threading.local()


def new_collection() -> None:
    _state.findings = []


def collected() -> list[dict]:
    return list(getattr(_state, "findings", []))


def _finding(tool_name: str, severity: str, summary: str, details: dict) -> dict:
    finding = {"tool": tool_name, "severity": severity, "summary": summary, "details": details}
    if not hasattr(_state, "findings"):
        _state.findings = []
    _state.findings.append(finding)
    return finding


# ========================================================================== #
# Tool 1 - breach check (k-anonymity)
# ========================================================================== #
HIBP_RANGE_URL = os.getenv("HIBP_RANGE_URL", "https://api.pwnedpasswords.com/range/")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
_UA = {"User-Agent": "CyberCheck-Agent (hackathon; privacy-preserving)"}


def _check_breach_impl(email: str) -> dict:
    value = (email or "").strip()
    if not value:
        return _finding("check_breach", "high", "No value was provided to check.", {})

    normalized = value.lower()
    sha1 = hashlib.sha1(normalized.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    # (a) k-anonymity credential-exposure check - nothing sensitive leaves the box
    ka_hits: int | None = None
    try:
        resp = requests.get(HIBP_RANGE_URL + prefix, headers=_UA, timeout=6)
        resp.raise_for_status()
        ka_hits = 0
        for line in resp.text.splitlines():
            h, _, count = line.partition(":")
            if h.strip().upper() == suffix:
                ka_hits = int(count.strip() or "0")
                break
    except (requests.RequestException, ValueError):
        ka_hits = None

    # (b) optional account-breach lookup - only if the operator opted in with a key
    account_breaches: list[dict] | None = None
    if HIBP_API_KEY and "@" in normalized:
        try:
            ar = requests.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/" + normalized,
                headers={**_UA, "hibp-api-key": HIBP_API_KEY},
                params={"truncateResponse": "false"},
                timeout=8,
            )
            if ar.status_code == 404:
                account_breaches = []
            elif ar.ok:
                account_breaches = [
                    {
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in ar.json()
                ]
        except (requests.RequestException, ValueError):
            account_breaches = None

    severity = "low"
    parts: list[str] = []

    if account_breaches:
        severity = "high"
        exposed = sorted({c for b in account_breaches for c in b.get("data_classes", [])})
        names = ", ".join(b["name"] for b in account_breaches[:5])
        parts.append(f"This address appears in {len(account_breaches)} known breach(es): {names}.")
        if exposed:
            parts.append("Exposed data types include " + ", ".join(exposed[:8]) + ".")
    elif account_breaches == []:
        parts.append("This address was not found in HaveIBeenPwned's account-breach list.")

    if ka_hits:
        severity = "high" if ka_hits > 10 else ("medium" if severity == "low" else severity)
        parts.append(
            f"The exact string was seen {ka_hits:,} time(s) in leaked-password corpora "
            "(matched via k-anonymity range check). If this is a password you use, change it now."
        )
    elif ka_hits == 0:
        parts.append("No match in the k-anonymity credential-exposure corpus.")

    if ka_hits is None and account_breaches is None:
        severity = "unknown"
        parts.append("Could not reach the breach databases; please try again later.")

    details = {
        "sha1_prefix_sent": prefix,
        "bytes_of_raw_value_sent": 0,
        "k_anonymity_hit_count": ka_hits,
        "account_breach_lookup_enabled": bool(HIBP_API_KEY),
        "account_breaches": account_breaches,
    }
    return _finding("check_breach", severity, " ".join(parts) or "No data returned.", details)


# ========================================================================== #
# Tool 2 - phishing / malicious-URL heuristics
# ========================================================================== #
POPULAR_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "instagram.com", "linkedin.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com", "coinbase.com", "binance.com",
    "dropbox.com", "github.com", "twitter.com", "x.com", "whatsapp.com",
    "gmail.com", "outlook.com", "office365.com", "icloud.com", "steamcommunity.com",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "country", "click",
    "link", "work", "support", "gdn", "loan", "review", "kim", "men", "download",
    "stream", "racing", "party", "science", "date", "faith", "cricket", "accountant",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "amazon", "microsoft", "google", "facebook", "instagram",
    "netflix", "bankofamerica", "wellsfargo", "chase", "coinbase", "binance",
    "dropbox", "github", "outlook", "office", "icloud", "whatsapp", "linkedin", "steam",
]

MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "co.za", "com.br", "com.mx",
}


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _check_phishing_impl(url: str) -> dict:
    raw = (url or "").strip()
    if not raw:
        return _finding("check_phishing", "high", "No URL was provided to check.", {})

    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    if not host:
        return _finding(
            "check_phishing", "medium",
            "Could not parse a hostname from this input.", {"raw_scheme": parsed.scheme},
        )

    score = 0
    signals: list[str] = []
    is_https = parsed.scheme == "https" or raw.lower().startswith("https://")
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    authority = raw.split("://", 1)[-1].split("/", 1)[0]

    if not is_https:
        score += 2
        signals.append("No HTTPS / secure scheme.")
    if is_ip:
        score += 3
        signals.append("Uses a raw IP address instead of a domain name.")
    if "@" in authority:
        score += 3
        signals.append("Contains an '@' before the host, which can hide the real destination.")
    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        signals.append("Uses punycode - characters that can visually imitate a real brand.")

    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        score += 2
        signals.append(f"Top-level domain .{tld} is frequently abused for scams.")
    if len(labels) >= 5:
        score += 1
        signals.append("Unusually many sub-domains.")
    if host.count("-") >= 3:
        score += 1
        signals.append("Many hyphens in the host name.")
    if len(host) > 40:
        score += 1
        signals.append("Very long host name.")

    reg = host if is_ip else _registrable(host)
    reg_label = reg.split(".")[0]

    for kw in BRAND_KEYWORDS:
        if kw in host and kw not in reg_label:
            score += 3
            signals.append(
                f"Mentions the brand '{kw}' in a sub-domain or path but is not an official "
                f"'{kw}' domain."
            )
            break

    typo_hit = None
    for good in POPULAR_DOMAINS:
        if 1 <= _levenshtein(reg, good) <= 2:
            typo_hit = good
            break
    if typo_hit:
        score += 3
        signals.append(f"Domain is a near-identical look-alike of {typo_hit} (possible typosquatting).")

    for token in ("secure", "login", "verify", "account", "update", "confirm", "signin", "webscr", "wallet"):
        if token in host:
            score += 1
            signals.append(f"Host contains alarming keyword '{token}'.")
            break

    age_days = None
    try:  # best-effort; python-whois is optional and can be slow/flaky
        import whois  # type: ignore

        info = whois.whois(reg)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            if 0 <= age_days < 90:
                score += 2
                signals.append(f"Domain was registered only {age_days} days ago.")
    except Exception:
        pass

    severity = "high" if score >= 5 else "medium" if score >= 2 else "low"
    if not signals:
        signals.append("No common phishing indicators found.")

    details = {
        "host": host,
        "registrable_domain": reg,
        "https": is_https,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "is_ip_literal": is_ip,
        "possible_typosquat_of": typo_hit,
        "domain_age_days": age_days,
        "heuristic_score": score,
        "signals": signals,
    }
    summary = f"Heuristic phishing score {score}. " + " ".join(signals)
    return _finding("check_phishing", severity, summary, details)


# ========================================================================== #
# Tool 3 - password strength (zxcvbn)
# ========================================================================== #
def _check_password_strength_impl(password: str) -> dict:
    if not password:
        return _finding("check_password_strength", "high", "No password was provided.", {})

    try:
        from zxcvbn import zxcvbn
    except ImportError:
        length = len(password)
        classes = sum(
            bool(re.search(p, password))
            for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
        )
        score = min(4, max(0, (length // 4) + classes - 2))
        severity = "high" if score <= 1 else "medium" if score == 2 else "low"
        return _finding(
            "check_password_strength", severity,
            f"Rough strength score {score}/4 (install zxcvbn for a precise estimate). "
            f"Length {length}, {classes} character classes.",
            {"length": length, "character_classes": classes, "score": score, "engine": "fallback"},
        )

    result = zxcvbn(password)
    score = int(result["score"])
    disp = result["crack_times_display"]
    feedback = result.get("feedback", {}) or {}
    severity = {0: "high", 1: "high", 2: "medium", 3: "low", 4: "low"}[score]
    verdict = {0: "very weak", 1: "weak", 2: "fair", 3: "strong", 4: "very strong"}[score]

    details = {
        "length": len(password),
        "zxcvbn_score": score,
        "guesses_log10": round(float(result["guesses_log10"]), 1),
        "estimated_crack_time_fast_offline": disp.get("offline_fast_hashing_1e10_per_second"),
        "estimated_crack_time_slow_offline": disp.get("offline_slow_hashing_1e4_per_second"),
        "estimated_crack_time_online_throttled": disp.get("online_throttling_100_per_hour"),
        "warning": feedback.get("warning") or "",
        "suggestions": feedback.get("suggestions") or [],
        "engine": "zxcvbn",
    }
    summary = (
        f"This password is {verdict} (zxcvbn score {score}/4). Estimated time to crack "
        f"offline with fast hardware: {disp.get('offline_fast_hashing_1e10_per_second')}."
    )
    if feedback.get("warning"):
        summary += f" Note: {feedback['warning']}."
    return _finding("check_password_strength", severity, summary, details)


# ========================================================================== #
# Strands tool wrappers (docstrings are what the model reads)
# ========================================================================== #
@tool
def check_breach(email: str) -> dict:
    """Check whether an email address (or a password string) has appeared in known
    data breaches. Privacy: the value is SHA-1 hashed locally and only the first
    five hex characters of that hash are sent to the breach API (k-anonymity); the
    raw value is never transmitted, logged, or stored. Use this for inputs of type
    'email'. Returns a structured finding with a severity and a short summary."""
    return _check_breach_impl(email)


@tool
def check_phishing(url: str) -> dict:
    """Assess whether a URL is likely to be phishing or malicious using heuristics:
    HTTPS presence, suspicious TLDs, raw-IP hosts, punycode, brand keywords in the
    wrong domain, typosquatting distance to popular domains, and (best-effort)
    domain age via WHOIS. Use this for inputs of type 'url'. Returns a structured
    finding with a severity and a short summary."""
    return _check_phishing_impl(url)


@tool
def check_password_strength(password: str) -> dict:
    """Estimate password strength with the zxcvbn library and report the estimated
    crack time and improvement tips. The raw password is never logged, stored, or
    echoed back - only derived metrics (length, score, crack-time estimates) are
    returned. Use this for inputs of type 'password'."""
    return _check_password_strength_impl(password)


# ========================================================================== #
# The single Strands agent
# ========================================================================== #
SYSTEM_PROMPT = """\
You are "CyberCheck", a calm, practical personal-security assistant.

Each request gives you one item to assess, as two lines:
  type: <email | url | password>
  value: <the item>

Tool selection:
  - type email    -> call check_breach
  - type url      -> call check_phishing
  - type password -> call check_password_strength
Call the single matching tool exactly once. Do not ask follow-up questions.

After the tool returns, write a short report for a non-technical person: 2-4
sentences covering what you checked, what was found, the overall risk (low,
medium, or high), and one or two concrete next steps. Plain sentences only - no
markdown, no bullet points, no headings.

Privacy: never repeat the raw email address, URL, or password in your reply.
Refer to it as "this address", "this link", or "this password". Do not invent
findings beyond what the tool reported.
"""


def build_agent():
    """Construct the Strands agent. Raises if the SDK / Bedrock access is missing -
    the endpoint catches that and falls back to calling the tools directly."""
    if Agent is None:
        raise RuntimeError("strands-agents is not installed")

    kwargs = {
        "system_prompt": SYSTEM_PROMPT,
        "tools": [check_breach, check_phishing, check_password_strength],
    }
    model_id = os.getenv("STRANDS_MODEL_ID")
    if model_id:
        kwargs["model"] = model_id  # otherwise Strands uses its default Bedrock model
    return Agent(**kwargs)


# ========================================================================== #
# Flask app
# ========================================================================== #
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cybercheck")

app = Flask(__name__)

try:
    from flask_cors import CORS

    CORS(app)
except ImportError:

    @app.after_request
    def _add_cors_headers(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        return resp


VALID_TYPES = {"email", "url", "password"}
_SEVERITY_RANK = {"low": 0, "unknown": 1, "medium": 1, "high": 2}

_agent = None


def get_agent():
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent


def _run_tool_directly(itype: str, value: str) -> None:
    if itype == "email":
        _check_breach_impl(value)
    elif itype == "url":
        _check_phishing_impl(value)
    elif itype == "password":
        _check_password_strength_impl(value)


def _aggregate_risk(findings: list[dict]) -> str:
    if not findings:
        return "medium"
    worst = max((f["severity"] for f in findings), key=lambda s: _SEVERITY_RANK.get(s, 1))
    return worst if worst in ("low", "medium", "high") else "medium"


def _fallback_summary(findings: list[dict], risk: str) -> str:
    if not findings:
        return "No checks were completed for this input."
    first = findings[0]
    tips = first["details"].get("suggestions") or []
    extra = f" Suggested next steps: {'; '.join(tips)}." if tips else ""
    return f"{first['summary']} Overall risk level: {risk}.{extra}"


@app.get("/")
def index():
    return jsonify(
        service="CyberCheck",
        endpoint="POST /api/check",
        body={"type": "email|url|password", "value": "<string>"},
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/check", methods=["POST", "OPTIONS"])
def check():
    if request.method == "OPTIONS":
        return ("", 204)

    body = request.get_json(silent=True) or {}
    itype = str(body.get("type", "")).strip().lower()
    value = body.get("value", "")

    if itype not in VALID_TYPES:
        return jsonify(error="'type' must be one of: email, url, password"), 400
    if not isinstance(value, str) or not value.strip():
        return jsonify(error="'value' must be a non-empty string"), 400

    new_collection()
    engine = "agent"
    summary = ""

    try:
        result = get_agent()(f"type: {itype}\nvalue: {value}")
        summary = str(result).strip()
    except Exception as exc:  # noqa: BLE001 - any agent/Bedrock failure -> direct mode
        engine = "direct"
        log.warning("Agent unavailable (%s); using direct tool dispatch.", exc.__class__.__name__)

    findings = collected()
    if not findings:
        _run_tool_directly(itype, value)
        findings = collected()
        if engine == "agent" and not summary:
            engine = "direct"

    risk = _aggregate_risk(findings)
    if not summary:
        summary = _fallback_summary(findings, risk)

    if len(findings) == 1:
        details = findings[0]["details"]
    else:
        details = {f["tool"]: f["details"] for f in findings}

    # NOTE: `value` is never logged.
    log.info(
        "check type=%s engine=%s risk=%s checks=%s",
        itype, engine, risk, [f["tool"] for f in findings],
    )

    return jsonify(
        risk_level=risk,
        summary=summary,
        details=details,
        checks=[f["tool"] for f in findings],
        engine=engine,
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=bool(os.getenv("FLASK_DEBUG")))
