"""CyberCheck - Personal Cybersecurity Checker Agent.

AWS "Agents for Humans" hackathon project. Single Strands agent + three security
tools, exposed over one Flask endpoint. Everything (backend + Chrome extension)
lives in this one folder.

Run:
    pip install -r requirements.txt
    python ai_extencion.py            # -> http://127.0.0.1:8000

Endpoint:
    POST /api/check   {"type": "email"|"url"|"password", "value": "<string>"}
    ->                {"risk_level": "low"|"medium"|"high", "summary": "...", "details": {...}}

Optional environment variables:
    STRANDS_MODEL_ID   Bedrock model id for the agent (else Strands default)
    AWS_REGION / AWS_* standard AWS creds -> enables the AI-written summary
    GSB_API_KEY        Google Safe Browsing key -> real threat-feed lookup for URLs
    HIBP_API_KEY       HaveIBeenPwned key -> email account-breach lookup
    API_KEY            if set, callers must send  X-API-Key: <value>
    RATE_LIMIT_PER_MIN requests per client IP per minute (default 120)
    CACHE_TTL_SECONDS  response cache lifetime (default 900)

Privacy:
    * check_breach            - only the first 5 chars of SHA-1(value) ever leave
                               the process (k-anonymity). Raw value never sent.
    * check_password_strength - raw password is never logged, stored, or echoed.
    * the cache is keyed by a salted hash, never by the raw value.
    * the backend never logs the `value` field.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from collections import OrderedDict, deque
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


_HTTP_TIMEOUT = 6
_UA = {"User-Agent": "CyberCheck-Agent (hackathon; privacy-preserving)"}


# ========================================================================== #
# Tool 1 - breach check (k-anonymity)
# ========================================================================== #
HIBP_RANGE_URL = os.getenv("HIBP_RANGE_URL", "https://api.pwnedpasswords.com/range/")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()


def _check_breach_impl(email: str) -> dict:
    value = (email or "").strip()
    if not value:
        return _finding("check_breach", "high", "No value was provided to check.", {})

    normalized = value.lower()
    looks_like_email = "@" in normalized and "." in normalized.split("@")[-1]
    sha1 = hashlib.sha1(normalized.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    # (a) k-anonymity credential-exposure check - nothing sensitive leaves the box
    ka_hits: int | None = None
    try:
        resp = requests.get(HIBP_RANGE_URL + prefix, headers=_UA, timeout=_HTTP_TIMEOUT)
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
    if HIBP_API_KEY and looks_like_email:
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
            f"This exact string was seen {ka_hits:,} time(s) in leaked-credential corpora "
            "(matched via k-anonymity range check). If you use it as a password anywhere, "
            "change it now."
        )
    elif ka_hits == 0:
        parts.append("No match in the k-anonymity leaked-credential corpus.")

    if ka_hits is None and account_breaches is None:
        severity = "unknown"
        parts.append("Could not reach the breach databases; please try again later.")

    if looks_like_email and not HIBP_API_KEY and account_breaches is None:
        parts.append(
            "Note: without an HaveIBeenPwned API key this only checks whether the address "
            "string itself leaked as a credential, not every breach it may appear in."
        )

    details = {
        "input_kind": "email" if looks_like_email else "credential-string",
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
    "bankofamerica.com", "wellsfargo.com", "citibank.com", "chase.com", "hsbc.com",
    "coinbase.com", "binance.com", "kraken.com", "metamask.io", "blockchain.com",
    "dropbox.com", "github.com", "gitlab.com", "twitter.com", "x.com",
    "whatsapp.com", "telegram.org", "gmail.com", "outlook.com", "office365.com",
    "office.com", "icloud.com", "yahoo.com", "steamcommunity.com", "steampowered.com",
    "roblox.com", "discord.com", "spotify.com", "booking.com", "airbnb.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com", "irs.gov",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "country", "click",
    "link", "work", "support", "gdn", "loan", "review", "kim", "men", "download",
    "stream", "racing", "party", "science", "date", "faith", "cricket", "accountant",
    "rest", "fit", "cam", "quest", "sbs", "cfd", "bond", "monster", "lol",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "icloud", "amazon", "microsoft", "office", "outlook",
    "google", "gmail", "facebook", "instagram", "whatsapp", "netflix", "spotify",
    "bankofamerica", "wellsfargo", "citibank", "chase", "hsbc", "revolut",
    "coinbase", "binance", "kraken", "metamask", "blockchain", "trustwallet",
    "dropbox", "github", "steam", "discord", "roblox", "telegram", "linkedin",
    "dhl", "fedex", "ups", "usps", "irs",
]

MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "co.za", "com.br", "com.mx", "com.tr", "com.ua", "co.in",
}

# Common homoglyph / leetspeak substitutions used in look-alike domains.
_DEHOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})

GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()


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


def _rdap_domain_age_days(registrable: str) -> int | None:
    """Registration age via RDAP (rdap.org). Faster and more reliable than WHOIS.
    Returns None on any failure."""
    try:
        r = requests.get(
            "https://rdap.org/domain/" + registrable, headers=_UA, timeout=4,
            allow_redirects=True,
        )
        if not r.ok:
            return None
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration" and event.get("eventDate"):
                created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - created).days
    except (requests.RequestException, ValueError, KeyError):
        return None
    return None


def _safe_browsing_threat(url: str) -> str | None:
    """Google Safe Browsing lookup. Returns the threat type string, or None."""
    if not GSB_API_KEY:
        return None
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": GSB_API_KEY},
            json={
                "client": {"clientId": "cybercheck", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=_HTTP_TIMEOUT,
        )
        if r.ok:
            matches = r.json().get("matches") or []
            if matches:
                return matches[0].get("threatType", "THREAT")
    except (requests.RequestException, ValueError):
        return None
    return None


def _check_phishing_impl(url: str) -> dict:
    raw = (url or "").strip()
    if not raw:
        return _finding("check_phishing", "high", "No URL was provided to check.", {})

    # If the user didn't type a scheme (just "google.com"), assume https and do
    # NOT penalise for "no HTTPS" - only an explicit "http://" is a red flag.
    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else "https://" + raw)
    host = (parsed.hostname or "").lower()
    if not host:
        return _finding(
            "check_phishing", "medium",
            "Could not parse a hostname from this input.", {"raw_scheme": parsed.scheme},
        )

    score = 0
    signals: list[str] = []
    explicit_http = raw.lower().startswith("http://")
    is_https = not explicit_http
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    authority = raw.split("://", 1)[-1].split("/", 1)[0]

    if explicit_http:
        score += 2
        signals.append("Uses plain HTTP instead of HTTPS.")
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

    # Typosquatting: near-miss of a popular domain, including homoglyph/leet swaps.
    typo_hit = None
    reg_norm = reg.translate(_DEHOMOGLYPH)
    for good in POPULAR_DOMAINS:
        d_raw = _levenshtein(reg, good)
        if d_raw == 0:
            break  # this IS the real domain
        d_norm = _levenshtein(reg_norm, good)
        # 1-2 edits from a real domain, OR a homoglyph swap that lands within 2.
        if (1 <= d_raw <= 2) or (reg_norm != reg and d_norm <= 2):
            typo_hit = good
            break
    if typo_hit:
        score += 3
        signals.append(f"Domain is a near-identical look-alike of {typo_hit} (possible typosquatting).")

    for token in ("secure", "login", "verify", "account", "update", "confirm",
                  "signin", "webscr", "wallet", "recover", "unlock", "billing"):
        if token in host:
            score += 1
            signals.append(f"Host contains alarming keyword '{token}'.")
            break

    # Domain age (RDAP) - skip for IPs and for well-known domains.
    age_days = None
    if not is_ip and reg not in POPULAR_DOMAINS:
        age_days = _rdap_domain_age_days(reg)
        if age_days is not None and 0 <= age_days < 90:
            score += 2
            signals.append(f"Domain was registered only {age_days} days ago.")

    # Google Safe Browsing threat feed (only if a key is configured).
    gsb_threat = _safe_browsing_threat(raw if has_scheme else "https://" + raw)
    if gsb_threat:
        score += 6
        signals.append(f"Google Safe Browsing flagged this URL as {gsb_threat}.")

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
        "safe_browsing_threat": gsb_threat,
        "heuristic_score": score,
        "signals": signals,
    }
    summary = f"Phishing risk score {score}. " + " ".join(signals)
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
    """Check whether an email address (or a credential string) has appeared in known
    data breaches. Privacy: the value is SHA-1 hashed locally and only the first
    five hex characters of that hash are sent to the breach API (k-anonymity); the
    raw value is never transmitted, logged, or stored. Use this for inputs of type
    'email'. Returns a structured finding with a severity and a short summary."""
    return _check_breach_impl(email)


@tool
def check_phishing(url: str) -> dict:
    """Assess whether a URL is likely to be phishing or malicious. Combines the
    Google Safe Browsing threat feed (when configured) with heuristics: HTTPS
    presence, suspicious TLDs, raw-IP hosts, punycode, brand keywords in the wrong
    domain, homoglyph/typosquatting distance to popular domains, alarming keywords,
    and domain age via RDAP. Use this for inputs of type 'url'. Returns a
    structured finding with a severity and a short summary."""
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
  - type password -> call check_password_strength, and also call check_breach on
                     the same value (a reused password may have leaked).
Call the matching tool(s) once each. Do not ask follow-up questions.

After the tool(s) return, write a short report for a non-technical person: 2-4
sentences covering what you checked, what was found, the overall risk (low,
medium, or high), and one or two concrete next steps. Plain sentences only - no
markdown, no bullet points, no headings.

Privacy: never repeat the raw email address, URL, or password in your reply.
Refer to it as "this address", "this link", or "this password". Do not invent
findings beyond what the tools reported.
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
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        return resp


VALID_TYPES = {"email", "url", "password"}
_SEVERITY_RANK = {"low": 0, "unknown": 1, "medium": 1, "high": 2}

API_KEY = os.getenv("API_KEY", "").strip()
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "900"))
_CACHE_SALT = os.getenv("CACHE_SALT", "cybercheck-v1")

_agent = None
_hits = {"cache": 0, "total": 0}

# --- tiny in-process TTL cache (keyed by a salted hash, never the raw value) --- #
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_cache_lock = threading.Lock()
_CACHE_MAX = 500


def _cache_key(itype: str, value: str) -> str:
    return hashlib.sha256(f"{_CACHE_SALT}\0{itype}\0{value}".encode("utf-8")).hexdigest()


def _cache_get(key: str):
    with _cache_lock:
        item = _cache.get(key)
        if not item:
            return None
        ts, payload = item
        if time.time() - ts > CACHE_TTL_SECONDS:
            _cache.pop(key, None)
            return None
        _cache.move_to_end(key)
        return payload


def _cache_put(key: str, payload: dict) -> None:
    with _cache_lock:
        _cache[key] = (time.time(), payload)
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)


# --- simple per-IP sliding-window rate limit --- #
_rl: "dict[str, deque]" = {}
_rl_lock = threading.Lock()


def _rate_limited(client_ip: str) -> bool:
    if RATE_LIMIT_PER_MIN <= 0:
        return False
    now = time.time()
    with _rl_lock:
        q = _rl.setdefault(client_ip, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MIN:
            return True
        q.append(now)
    return False


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
        _check_breach_impl(value)


def _aggregate_risk(findings: list[dict]) -> str:
    if not findings:
        return "medium"
    worst = max((f["severity"] for f in findings), key=lambda s: _SEVERITY_RANK.get(s, 1))
    return worst if worst in ("low", "medium", "high") else "medium"


def _collect_signals(findings: list[dict]) -> list[str]:
    out: list[str] = []
    for f in findings:
        d = f.get("details") or {}
        out.extend(d.get("signals") or [])
        if d.get("warning"):
            out.append(d["warning"])
        for tip in d.get("suggestions") or []:
            out.append(tip)
    # de-dupe, keep order
    seen = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def _fallback_summary(findings: list[dict], risk: str) -> str:
    if not findings:
        return "No checks were completed for this input."
    lead = "; ".join(f["summary"].rstrip(".") for f in findings)
    return f"{lead}. Overall risk level: {risk}."


@app.get("/")
def index():
    return jsonify(
        service="CyberCheck",
        endpoint="POST /api/check",
        body={"type": "email|url|password", "value": "<string>"},
        auth_required=bool(API_KEY),
    )


@app.get("/health")
def health():
    return jsonify(
        status="ok",
        agent_configured=Agent is not None and bool(os.getenv("AWS_REGION") or os.getenv("AWS_ACCESS_KEY_ID")),
        safe_browsing=bool(GSB_API_KEY),
        cache_entries=len(_cache),
    )


@app.route("/api/check", methods=["POST", "OPTIONS"])
def check():
    if request.method == "OPTIONS":
        return ("", 204)

    if API_KEY and request.headers.get("X-API-Key", "") != API_KEY:
        return jsonify(error="missing or invalid X-API-Key"), 401

    client_ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "?")).split(",")[0].strip()
    if _rate_limited(client_ip):
        return jsonify(error="rate limit exceeded, slow down"), 429

    body = request.get_json(silent=True) or {}
    itype = str(body.get("type", "")).strip().lower()
    value = body.get("value", "")

    if itype not in VALID_TYPES:
        return jsonify(error="'type' must be one of: email, url, password"), 400
    if not isinstance(value, str) or not value.strip():
        return jsonify(error="'value' must be a non-empty string"), 400
    if len(value) > 2048:
        return jsonify(error="'value' is too long (max 2048 chars)"), 400

    _hits["total"] += 1
    key = _cache_key(itype, value)
    cached = _cache_get(key)
    if cached is not None:
        _hits["cache"] += 1
        return jsonify({**cached, "cached": True})

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

    payload = {
        "risk_level": risk,
        "summary": summary,
        "signals": _collect_signals(findings),
        "details": details,
        "checks": [f["tool"] for f in findings],
        "engine": engine,
        "cached": False,
    }
    _cache_put(key, payload)

    # NOTE: `value` is never logged.
    log.info(
        "check type=%s engine=%s risk=%s checks=%s ip=%s cache=%d/%d",
        itype, engine, risk, payload["checks"], client_ip, _hits["cache"], _hits["total"],
    )
    return jsonify(payload)


if __name__ == "__main__":
    # Port 8000 by default: on macOS, port 5000 is taken by AirPlay Receiver.
    port = int(os.getenv("PORT", "8000"))
    app.run(host="127.0.0.1", port=port, debug=bool(os.getenv("FLASK_DEBUG")))
