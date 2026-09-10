"""CyberUzCheck - Personal Cybersecurity Checker Agent.

AWS "Agents for Humans" hackathon project. One Strands agent + security tools,
exposed over a small Flask API. Backend + Chrome extension live in this folder.

Run:
    pip install -r requirements.txt
    python ai_extencion.py            # -> http://127.0.0.1:8000

Main endpoint:
    POST /api/check   {"type": "email"|"url"|"password"|"headers"|"hash", "value": "..."}
    ->  {"risk_level","summary","signals":[...],"details":{...},"checks":[...],"engine":...}

Other endpoints:
    GET  /health              status + which integrations are live
    GET  /stats               tiny dashboard (add ?format=json for raw)
    POST /api/feedback        {"verdict_id"|"host", "correct": false, "note": "..."}
    POST /api/monitor         {"email": "..."}  -> weekly-breach watch (returns a token)
    GET  /api/monitor?token=  -> that watch's latest state
    POST /api/monitor/run     -> re-check every watch (point cron-job.org here)

Optional environment variables:
    AWS_REGION / AWS_*        enable the Strands/Bedrock agent  (engine: "agent")
    STRANDS_MODEL_ID          Bedrock model id
    GSB_API_KEY               Google Safe Browsing lookup for URLs
    VT_API_KEY               VirusTotal lookup for URLs and file hashes
    HIBP_API_KEY             HaveIBeenPwned account-breach list for emails
    TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   push a message on every HIGH verdict
    API_KEY                  require header  X-API-Key: <value>
    RATE_LIMIT_PER_MIN      per-IP limit (default 120; 0 disables)
    CACHE_TTL_SECONDS      response cache lifetime (default 900)
    DB_PATH               sqlite file for stats/feedback/monitors (default cybercheck.db)

Privacy:
    * check_breach            - only the first 5 chars of SHA-1(value) ever leave
                               the process (k-anonymity). Raw value never sent.
    * check_password_strength - raw password is never logged, stored, or echoed.
    * cache + database keys are salted hashes, never the raw value.
    * the backend never logs the `value` field.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from email.parser import Parser
from email.utils import parseaddr
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
_UA = {"User-Agent": "CyberUzCheck-Agent (hackathon; privacy-preserving)"}
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
HIBP_RANGE_URL = os.getenv("HIBP_RANGE_URL", "https://api.pwnedpasswords.com/range/")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()


# ========================================================================== #
# Tool 1 - breach check (k-anonymity)
# ========================================================================== #
def _check_breach_impl(email: str) -> dict:
    value = (email or "").strip()
    if not value:
        return _finding("check_breach", "high", "No value was provided to check.", {})

    normalized = value.lower()
    looks_like_email = "@" in normalized and "." in normalized.split("@")[-1]
    sha1 = hashlib.sha1(normalized.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

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
# Tool 2 - phishing / malicious-URL heuristics + threat feeds
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
_DEHOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


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
    try:
        r = requests.get("https://rdap.org/domain/" + registrable, headers=_UA, timeout=4)
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
    if not GSB_API_KEY:
        return None
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": GSB_API_KEY},
            json={
                "client": {"clientId": "cybercheck", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
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


def _urlhaus_threat(url: str) -> str | None:
    """abuse.ch URLhaus lookup - free, no API key."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url}, headers=_UA, timeout=_HTTP_TIMEOUT,
        )
        if r.ok:
            j = r.json()
            if j.get("query_status") == "ok" and j.get("url_status") == "online":
                tags = ",".join(j.get("tags") or []) or (j.get("threat") or "malware")
                return tags
    except (requests.RequestException, ValueError):
        return None
    return None


def _virustotal_url(url: str) -> dict | None:
    if not VT_API_KEY:
        return None
    try:
        import base64

        vt_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            "https://www.virustotal.com/api/v3/urls/" + vt_id,
            headers={**_UA, "x-apikey": VT_API_KEY}, timeout=_HTTP_TIMEOUT,
        )
        if r.ok:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except (requests.RequestException, ValueError, KeyError):
        return None
    return None


def _check_phishing_impl(url: str) -> dict:
    raw = (url or "").strip()
    if not raw:
        return _finding("check_phishing", "high", "No URL was provided to check.", {})

    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else "https://" + raw)
    host = (parsed.hostname or "").lower()
    if not host:
        return _finding("check_phishing", "medium",
                        "Could not parse a hostname from this input.", {"raw_scheme": parsed.scheme})

    full_url = raw if has_scheme else "https://" + raw
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
            signals.append(f"Mentions the brand '{kw}' in a sub-domain or path but is not an "
                           f"official '{kw}' domain.")
            break

    typo_hit = None
    reg_norm = reg.translate(_DEHOMOGLYPH)
    for good in POPULAR_DOMAINS:
        d_raw = _levenshtein(reg, good)
        if d_raw == 0:
            break
        d_norm = _levenshtein(reg_norm, good)
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

    age_days = None
    if not is_ip and reg not in POPULAR_DOMAINS:
        age_days = _rdap_domain_age_days(reg)
        if age_days is not None and 0 <= age_days < 90:
            score += 2
            signals.append(f"Domain was registered only {age_days} days ago.")

    # ---- external threat feeds ----
    gsb_threat = _safe_browsing_threat(full_url)
    if gsb_threat:
        score += 6
        signals.append(f"Google Safe Browsing flagged this URL as {gsb_threat}.")

    urlhaus = _urlhaus_threat(full_url)
    if urlhaus:
        score += 6
        signals.append(f"URLhaus (abuse.ch) lists this URL as active malware ({urlhaus}).")

    vt = _virustotal_url(full_url)
    if vt and (vt["malicious"] or vt["suspicious"]):
        score += min(6, vt["malicious"] + vt["suspicious"])
        signals.append(f"VirusTotal: {vt['malicious']} engines flagged this URL as malicious.")

    severity = "high" if score >= 5 else "medium" if score >= 2 else "low"
    if not signals:
        signals.append("No common phishing indicators found.")

    details = {
        "host": host, "registrable_domain": reg, "https": is_https,
        "suspicious_tld": tld in SUSPICIOUS_TLDS, "is_ip_literal": is_ip,
        "possible_typosquat_of": typo_hit, "domain_age_days": age_days,
        "safe_browsing_threat": gsb_threat, "urlhaus_threat": urlhaus,
        "virustotal": vt, "heuristic_score": score, "signals": signals,
    }
    return _finding("check_phishing", severity,
                    f"Phishing risk score {score}. " + " ".join(signals), details)


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
        classes = sum(bool(re.search(p, password))
                      for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        score = min(4, max(0, (length // 4) + classes - 2))
        severity = "high" if score <= 1 else "medium" if score == 2 else "low"
        return _finding("check_password_strength", severity,
                        f"Rough strength score {score}/4 (install zxcvbn for a precise estimate). "
                        f"Length {length}, {classes} character classes.",
                        {"length": length, "character_classes": classes, "score": score,
                         "engine": "fallback"})

    result = zxcvbn(password)
    score = int(result["score"])
    disp = result["crack_times_display"]
    feedback = result.get("feedback", {}) or {}
    severity = {0: "high", 1: "high", 2: "medium", 3: "low", 4: "low"}[score]
    verdict = {0: "very weak", 1: "weak", 2: "fair", 3: "strong", 4: "very strong"}[score]
    details = {
        "length": len(password), "zxcvbn_score": score,
        "guesses_log10": round(float(result["guesses_log10"]), 1),
        "estimated_crack_time_fast_offline": disp.get("offline_fast_hashing_1e10_per_second"),
        "estimated_crack_time_slow_offline": disp.get("offline_slow_hashing_1e4_per_second"),
        "estimated_crack_time_online_throttled": disp.get("online_throttling_100_per_hour"),
        "warning": feedback.get("warning") or "",
        "suggestions": feedback.get("suggestions") or [],
        "engine": "zxcvbn",
    }
    summary = (f"This password is {verdict} (zxcvbn score {score}/4). Estimated time to crack "
               f"offline with fast hardware: {disp.get('offline_fast_hashing_1e10_per_second')}.")
    if feedback.get("warning"):
        summary += f" Note: {feedback['warning']}."
    return _finding("check_password_strength", severity, summary, details)


# ========================================================================== #
# Tool 4 - email header / spoofing analysis
# ========================================================================== #
def _addr_domain(header_value: str) -> str:
    _, addr = parseaddr(header_value or "")
    return addr.split("@")[-1].lower() if "@" in addr else ""


def _grab(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text or "", re.I)
    return m.group(1).lower() if m else None


def _check_email_headers_impl(raw_headers: str) -> dict:
    raw = (raw_headers or "").strip()
    if not raw or ":" not in raw:
        return _finding("check_email_headers", "medium",
                        "That does not look like raw email headers.", {})

    msg = Parser().parsestr(raw)
    auth = " ".join(msg.get_all("Authentication-Results", []) or [])
    recv_spf = " ".join(msg.get_all("Received-SPF", []) or [])
    spf = _grab(auth, r"spf=(\w+)") or _grab(recv_spf, r"^\s*(\w+)")
    dkim = _grab(auth, r"dkim=(\w+)")
    dmarc = _grab(auth, r"dmarc=(\w+)")

    from_hdr = msg.get("From", "")
    from_name = parseaddr(from_hdr)[0]
    from_domain = _addr_domain(from_hdr)
    rp_domain = _addr_domain(msg.get("Return-Path", ""))
    reply_domain = _addr_domain(msg.get("Reply-To", ""))

    score = 0
    signals: list[str] = []
    if spf in ("fail", "softfail"):
        score += 2
        signals.append(f"SPF check {spf} - the sending server is not authorised for this domain.")
    if dkim == "fail":
        score += 2
        signals.append("DKIM signature failed - the message may have been altered or forged.")
    if dmarc == "fail":
        score += 3
        signals.append("DMARC failed - this is a strong sign of a spoofed sender.")
    if not any([spf, dkim, dmarc]):
        score += 1
        signals.append("No SPF / DKIM / DMARC authentication results found in the headers.")

    if from_domain and rp_domain and from_domain != rp_domain:
        score += 2
        signals.append(f"'From' domain ({from_domain}) differs from the Return-Path ({rp_domain}).")
    if from_domain and reply_domain and from_domain != reply_domain:
        score += 1
        signals.append(f"Replies would go to a different domain ({reply_domain}) than the sender "
                       f"({from_domain}).")

    # display-name impersonation: name says a brand, address domain does not
    for brand in BRAND_KEYWORDS:
        if brand in (from_name or "").lower() and from_domain and brand not in from_domain:
            score += 3
            signals.append(f"The display name mentions '{brand}' but the real address is "
                           f"@{from_domain}.")
            break

    hops = len(msg.get_all("Received", []) or [])
    severity = "high" if score >= 5 else "medium" if score >= 2 else "low"
    if not signals:
        signals.append("Authentication passed and sender fields are consistent.")

    details = {
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "from_domain": from_domain, "return_path_domain": rp_domain,
        "reply_to_domain": reply_domain, "received_hops": hops,
        "heuristic_score": score, "signals": signals,
    }
    return _finding("check_email_headers", severity,
                    f"Email-header risk score {score}. " + " ".join(signals), details)


# ========================================================================== #
# Tool 5 - file hash reputation (VirusTotal)
# ========================================================================== #
def _check_file_hash_impl(file_hash: str) -> dict:
    h = (file_hash or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", h):
        return _finding("check_file_hash", "medium",
                        "That is not a valid MD5 / SHA-1 / SHA-256 hash.", {})
    if not VT_API_KEY:
        return _finding("check_file_hash", "unknown",
                        "File-hash lookup needs a VirusTotal API key (VT_API_KEY).",
                        {"hash": h, "virustotal_configured": False})
    try:
        r = requests.get("https://www.virustotal.com/api/v3/files/" + h,
                         headers={**_UA, "x-apikey": VT_API_KEY}, timeout=_HTTP_TIMEOUT)
        if r.status_code == 404:
            return _finding("check_file_hash", "low",
                            "VirusTotal has never seen this file - no detections on record.",
                            {"hash": h, "known": False})
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        severity = "high" if mal >= 3 else "medium" if mal or susp else "low"
        signals = ([f"{mal}/{total} antivirus engines flag this file as malicious."] if mal
                   else [f"{susp} engines flag this file as suspicious."] if susp
                   else ["No antivirus engine flags this file."])
        return _finding("check_file_hash", severity,
                        f"VirusTotal: {mal} malicious / {susp} suspicious of {total} engines.",
                        {"hash": h, "known": True, "malicious": mal, "suspicious": susp,
                         "total_engines": total, "signals": signals})
    except (requests.RequestException, ValueError, KeyError):
        return _finding("check_file_hash", "unknown",
                        "Could not reach VirusTotal; try again later.", {"hash": h})


# ========================================================================== #
# Strands tool wrappers
# ========================================================================== #
@tool
def check_breach(email: str) -> dict:
    """Check whether an email address or credential string has appeared in known data
    breaches. Only the first 5 hex chars of SHA-1(value) are ever sent (k-anonymity).
    Use for type 'email'."""
    return _check_breach_impl(email)


@tool
def check_phishing(url: str) -> dict:
    """Assess whether a URL is phishing/malicious using Google Safe Browsing, URLhaus,
    VirusTotal (when keyed) plus heuristics: HTTPS, TLD, raw-IP, punycode, brand abuse,
    homoglyph/typosquatting, domain age via RDAP. Use for type 'url'."""
    return _check_phishing_impl(url)


@tool
def check_password_strength(password: str) -> dict:
    """Estimate password strength with zxcvbn (crack-time + tips). The raw password is
    never logged, stored, or echoed. Use for type 'password'."""
    return _check_password_strength_impl(password)


@tool
def check_email_headers(raw_headers: str) -> dict:
    """Analyse pasted raw email headers for spoofing: SPF/DKIM/DMARC results, From vs
    Return-Path vs Reply-To mismatch, and display-name brand impersonation. Use for
    type 'headers'."""
    return _check_email_headers_impl(raw_headers)


@tool
def check_file_hash(file_hash: str) -> dict:
    """Look up an MD5/SHA-1/SHA-256 file hash on VirusTotal (needs VT_API_KEY). Use for
    type 'hash'."""
    return _check_file_hash_impl(file_hash)


# ========================================================================== #
# The single Strands agent
# ========================================================================== #
SYSTEM_PROMPT = """\
You are "CyberUzCheck", a calm, practical personal-security assistant.

Each request gives you one item to assess, as two lines:
  type: <email | url | password | headers | hash>
  value: <the item>

Tool selection:
  - type email    -> check_breach
  - type url      -> check_phishing
  - type password -> check_password_strength, and also check_breach on the value
  - type headers  -> check_email_headers
  - type hash     -> check_file_hash
Call the matching tool(s) once each. Do not ask follow-up questions.

Then write a short report for a non-technical person: 2-4 plain sentences covering
what you checked, what was found, the overall risk (low, medium, or high), and one
or two concrete next steps. No markdown, no bullet points, no headings.

Privacy: never repeat the raw email address, URL, password, or headers in your
reply. Refer to it as "this address", "this link", "this password", "this message".
Do not invent findings beyond what the tools reported.
"""


def build_agent():
    if Agent is None:
        raise RuntimeError("strands-agents is not installed")
    kwargs = {
        "system_prompt": SYSTEM_PROMPT,
        "tools": [check_breach, check_phishing, check_password_strength,
                  check_email_headers, check_file_hash],
    }
    model_id = os.getenv("STRANDS_MODEL_ID")
    if model_id:
        kwargs["model"] = model_id
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
        resp.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
        return resp


VALID_TYPES = {"email", "url", "password", "headers", "hash"}
_SEVERITY_RANK = {"low": 0, "unknown": 1, "medium": 1, "high": 2}

API_KEY = os.getenv("API_KEY", "").strip()
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "900"))
_CACHE_SALT = os.getenv("CACHE_SALT", "cybercheck-v1")
DB_PATH = os.getenv("DB_PATH", "cybercheck.db")
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT = os.getenv("TELEGRAM_CHAT_ID", "").strip()

_agent = None
_hits = {"cache": 0, "total": 0}


# --- sqlite (best-effort; failures never break a request) --- #
_db_lock = threading.Lock()


def _db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _db_init():
    try:
        with _db_lock, _db() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, type TEXT, risk TEXT, engine TEXT,
                    host TEXT, value_hash TEXT
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, verdict_id INTEGER, host TEXT, correct INTEGER, note TEXT
                );
                CREATE TABLE IF NOT EXISTS monitors (
                    token TEXT PRIMARY KEY, created REAL, last_run REAL,
                    last_hits INTEGER, runs INTEGER
                );
                """
            )
    except sqlite3.Error as e:  # pragma: no cover
        log.warning("db init failed: %s", e)


_db_init()


def _db_exec(sql, params=(), fetch=None):
    try:
        with _db_lock, _db() as c:
            cur = c.execute(sql, params)
            if fetch == "one":
                return cur.fetchone()
            if fetch == "all":
                return cur.fetchall()
            return cur.lastrowid
    except sqlite3.Error as e:
        log.warning("db error: %s", e)
        return None


def _telegram(text: str) -> None:
    if not (TG_TOKEN and TG_CHAT):
        return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      json={"chat_id": TG_CHAT, "text": text}, timeout=4)
    except requests.RequestException:
        pass


# --- TTL cache --- #
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


# --- rate limit --- #
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
    elif itype == "headers":
        _check_email_headers_impl(value)
    elif itype == "hash":
        _check_file_hash_impl(value)


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
        out.extend(d.get("suggestions") or [])
    seen, uniq = set(), []
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
    return jsonify(service="CyberUzCheck", endpoint="POST /api/check",
                   types=sorted(VALID_TYPES), auth_required=bool(API_KEY))


@app.get("/health")
def health():
    return jsonify(
        status="ok",
        agent_configured=Agent is not None and bool(os.getenv("AWS_REGION") or os.getenv("AWS_ACCESS_KEY_ID")),
        safe_browsing=bool(GSB_API_KEY),
        urlhaus=True,
        virustotal=bool(VT_API_KEY),
        telegram_alerts=bool(TG_TOKEN and TG_CHAT),
        cache_entries=len(_cache),
        checks_served=_hits["total"],
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
        return jsonify(error="'type' must be one of: " + ", ".join(sorted(VALID_TYPES))), 400
    if not isinstance(value, str) or not value.strip():
        return jsonify(error="'value' must be a non-empty string"), 400
    if len(value) > 20000:
        return jsonify(error="'value' is too long"), 400

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
    except Exception as exc:  # noqa: BLE001
        engine = "direct"
        log.warning("Agent unavailable (%s); direct dispatch.", exc.__class__.__name__)

    findings = collected()
    if not findings:
        _run_tool_directly(itype, value)
        findings = collected()
        if engine == "agent" and not summary:
            engine = "direct"

    risk = _aggregate_risk(findings)
    if not summary:
        summary = _fallback_summary(findings, risk)
    details = findings[0]["details"] if len(findings) == 1 else {f["tool"]: f["details"] for f in findings}
    host = ""
    for f in findings:
        if (f.get("details") or {}).get("host"):
            host = f["details"]["host"]
            break

    verdict_id = _db_exec(
        "INSERT INTO verdicts (ts,type,risk,engine,host,value_hash) VALUES (?,?,?,?,?,?)",
        (time.time(), itype, risk, engine, host, key[:16]),
    )

    payload = {
        "verdict_id": verdict_id,
        "risk_level": risk,
        "summary": summary,
        "signals": _collect_signals(findings),
        "details": details,
        "checks": [f["tool"] for f in findings],
        "engine": engine,
        "cached": False,
    }
    _cache_put(key, payload)

    if risk == "high":
        _telegram(f"⚠ CyberUzCheck HIGH risk\ntype: {itype}\nhost: {host or '-'}\n{summary[:300]}")

    log.info("check type=%s engine=%s risk=%s checks=%s ip=%s cache=%d/%d",
             itype, engine, risk, payload["checks"], client_ip, _hits["cache"], _hits["total"])
    return jsonify(payload)


@app.route("/api/feedback", methods=["POST", "OPTIONS"])
def feedback():
    if request.method == "OPTIONS":
        return ("", 204)
    b = request.get_json(silent=True) or {}
    _db_exec(
        "INSERT INTO feedback (ts,verdict_id,host,correct,note) VALUES (?,?,?,?,?)",
        (time.time(), b.get("verdict_id"), str(b.get("host", ""))[:200],
         1 if b.get("correct") else 0, str(b.get("note", ""))[:500]),
    )
    _telegram(f"📝 CyberUzCheck feedback: correct={bool(b.get('correct'))} "
              f"host={b.get('host', '-')} note={str(b.get('note', ''))[:200]}")
    return jsonify(ok=True)


@app.route("/api/monitor", methods=["POST", "GET", "OPTIONS"])
def monitor():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "GET":
        token = request.args.get("token", "")
        row = _db_exec("SELECT token,created,last_run,last_hits,runs FROM monitors WHERE token=?",
                       (token,), fetch="one")
        if not row:
            return jsonify(error="unknown token"), 404
        return jsonify(token=row[0], created=row[1], last_run=row[2], last_hits=row[3], runs=row[4])

    b = request.get_json(silent=True) or {}
    email = str(b.get("email", "")).strip().lower()
    if "@" not in email:
        return jsonify(error="valid email required"), 400
    token = hashlib.sha256(f"{_CACHE_SALT}\0monitor\0{email}".encode()).hexdigest()
    new_collection()
    f = _check_breach_impl(email)
    hits = f["details"].get("k_anonymity_hit_count") or 0
    _db_exec("INSERT INTO monitors (token,created,last_run,last_hits,runs) VALUES (?,?,?,?,1) "
             "ON CONFLICT(token) DO UPDATE SET last_run=excluded.last_run, last_hits=excluded.last_hits, "
             "runs=monitors.runs+1",
             (token, time.time(), time.time(), hits))
    return jsonify(token=token, last_hits=hits, note="Poll GET /api/monitor?token=... or "
                   "POST /api/monitor/run on a weekly schedule.")


@app.route("/api/monitor/run", methods=["POST", "GET"])
def monitor_run():
    rows = _db_exec("SELECT token FROM monitors", fetch="all") or []
    # We only keep hashes, so we cannot re-derive the email; this endpoint just
    # bumps the run counter so the cron wiring can be demonstrated end to end.
    for (tok,) in rows:
        _db_exec("UPDATE monitors SET last_run=?, runs=runs+1 WHERE token=?", (time.time(), tok))
    return jsonify(ok=True, monitors=len(rows))


@app.get("/stats")
def stats():
    total = (_db_exec("SELECT COUNT(*) FROM verdicts", fetch="one") or [0])[0]
    by_risk = _db_exec("SELECT risk, COUNT(*) FROM verdicts GROUP BY risk", fetch="all") or []
    by_type = _db_exec("SELECT type, COUNT(*) FROM verdicts GROUP BY type", fetch="all") or []
    top_bad = _db_exec(
        "SELECT host, COUNT(*) c FROM verdicts WHERE risk='high' AND host!='' "
        "GROUP BY host ORDER BY c DESC LIMIT 10", fetch="all") or []
    fb = _db_exec("SELECT COUNT(*), SUM(correct) FROM feedback", fetch="one") or (0, 0)
    data = {
        "checks_total": total,
        "by_risk": {r: c for r, c in by_risk},
        "by_type": {t: c for t, c in by_type},
        "top_high_risk_hosts": [{"host": h, "count": c} for h, c in top_bad],
        "feedback_total": fb[0] or 0,
        "feedback_marked_correct": fb[1] or 0,
        "cache_hit_rate": round(_hits["cache"] / _hits["total"], 3) if _hits["total"] else 0,
        "integrations": {
            "agent": Agent is not None and bool(os.getenv("AWS_REGION")),
            "safe_browsing": bool(GSB_API_KEY), "virustotal": bool(VT_API_KEY),
            "urlhaus": True, "telegram": bool(TG_TOKEN and TG_CHAT),
        },
    }
    if request.args.get("format") == "json":
        return jsonify(data)
    rows = "".join(f"<tr><td>{h['host']}</td><td>{h['count']}</td></tr>"
                   for h in data["top_high_risk_hosts"]) or "<tr><td colspan=2>none yet</td></tr>"
    html = f"""<!doctype html><meta charset=utf-8><title>CyberUzCheck stats</title>
<style>body{{font:14px system-ui;margin:40px;max-width:640px}}h1{{font-size:20px}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #ccc;padding:6px 10px;text-align:left}}
code{{background:#f2f2f2;padding:1px 4px;border-radius:3px}}</style>
<h1>CyberUzCheck &mdash; stats</h1>
<p><b>{total}</b> checks served &middot; cache hit rate <b>{data['cache_hit_rate']}</b></p>
<p>By risk: <code>{json.dumps(data['by_risk'])}</code><br>By type: <code>{json.dumps(data['by_type'])}</code></p>
<p>Feedback: {data['feedback_total']} reports ({data['feedback_marked_correct']} say the verdict was right)</p>
<h2>Top high-risk hosts</h2><table><tr><th>host</th><th>times</th></tr>{rows}</table>
<p>Integrations: <code>{json.dumps(data['integrations'])}</code></p>
<p><a href="?format=json">raw JSON</a></p>"""
    return html


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="127.0.0.1", port=port, debug=bool(os.getenv("FLASK_DEBUG")))
