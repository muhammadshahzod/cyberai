# CyberCheck — Personal Cybersecurity Checker Agent

An **AWS "Agents for Humans"** hackathon project built on the **Strands Agents SDK**.

CyberCheck is one AI agent that helps a non-technical person answer: **"Is this safe?"**
— for an email address, a link, or a password. A Chrome extension is the front
door; a single-file Flask backend hosts the agent and its three security tools.

Everything lives in this one folder.

---

## What it does

| Input (`type`) | Agent calls | You get |
|---|---|---|
| **email** | `check_breach` | leaked-credential match (k-anonymity) + optional HIBP account-breach list |
| **url** | `check_phishing` | Google Safe Browsing + URLhaus + VirusTotal + heuristics (typosquatting/homoglyph, punycode, brand abuse, TLD, RDAP domain age) |
| **password** | `check_password_strength` + `check_breach` | zxcvbn crack-time + tips, and whether the exact string has leaked |
| **headers** | `check_email_headers` | SPF/DKIM/DMARC results, From vs Return-Path vs Reply-To mismatch, display-name brand impersonation |
| **hash** | `check_file_hash` | VirusTotal reputation for an MD5/SHA-1/SHA-256 file hash |

Plus, in the extension: **proactive site blocking**, a **password-entry warning
bar** on suspicious pages, a **toolbar badge** coloured by the current tab's risk,
**right-click checks**, **"report as wrong"**, a **`/stats` dashboard**, and an
optional **Telegram alert** on every HIGH verdict.

Response shape:

```json
{
  "risk_level": "low" | "medium" | "high",
  "summary": "plain-language report (written by the agent when AWS is configured)",
  "signals": ["human-readable warning / ok / tip lines"],
  "details": { "...tool-specific fields..." },
  "checks": ["check_phishing"],
  "engine": "agent" | "direct",
  "cached": false
}
```

---

## Architecture

```
┌──────────────────────────────┐            ┌──────────────────────────────────────────────┐
│  Chrome extension (MV3)        │            │        Flask backend (ai_extencion.py)         │
│                              │  POST JSON   │                                              │
│  popup.js  — input + result   │ ───────────► │  POST /api/check {type,value}                 │
│  background.js — context menu, │            │   ├─ API-key gate (optional)                  │
│      desktop notifications     │ ◄────────── │   ├─ per-IP rate limit                        │
│  content.js — flags mismatched │  JSON reply │   ├─ salted-hash TTL cache                    │
│      links inline on any page  │            │   └─ Strands Agent  ─┐                        │
└──────────────────────────────┘            │        (routes by type)                       │
                                            │        ├─ check_breach   → HIBP range (k-anon) │
                                            │        ├─ check_phishing → Safe Browsing + RDAP│
                                            │        └─ check_password → zxcvbn (local)      │
                                            │   aggregate → {risk_level, summary, signals}   │
                                            └──────────────────────────────────────────────┘
```

If the Strands SDK / Bedrock access isn't configured the endpoint falls back to
calling the tools directly (`engine: "direct"`) — the demo works with or without AWS.

---

## Folder contents

```
ai_extencion.py   backend: 3 tools + Strands agent + Flask endpoint + cache/limit/auth
manifest.json     Chrome extension, Manifest V3
popup.html/.js/.css   toolbar popup (risk card, signals list, history, backend probe)
background.js      service worker: right-click "Check with CyberCheck", notifications
content.js         in-page: outlines links whose text/href domains disagree (100% local)
icon16/48/128.png  shield icons  (regenerate with:  python make_icons.py)
Procfile / render.yaml   deploy config
requirements.txt   runtime deps
test_app.py        pytest suite
DEPLOY.md          Render / Railway / Fly deployment guide
```

---

## Run the backend locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python ai_extencion.py            # http://127.0.0.1:8000   (8000: macOS AirPlay owns 5000)
```

Test:

```bash
curl -s localhost:8000/api/check -H 'Content-Type: application/json' \
  -d '{"type":"url","value":"https://g00gle.com"}' | python3 -m json.tool
```

Run tests: `pip install pytest && pytest -q`

---

## Environment variables (all optional)

| Var | Effect |
|---|---|
| `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | enables the Strands/Bedrock agent → `engine: "agent"` with an AI-written summary |
| `STRANDS_MODEL_ID` | pick the Bedrock model (else Strands default) |
| `GSB_API_KEY` | [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) key → real threat-feed lookup in `check_phishing` |
| `HIBP_API_KEY` | [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) key → email account-breach list in `check_breach` |
| `API_KEY` | if set, callers must send header `X-API-Key: <value>` |
| `RATE_LIMIT_PER_MIN` | requests per client IP per minute (default 120; 0 disables) |
| `CACHE_TTL_SECONDS` | response cache lifetime (default 900) |

---

## Chrome extension

1. `chrome://extensions` → **Developer mode** on → **Load unpacked** → this folder.
2. Toolbar icon → paste an email / link / password → **Check**
   (or **This tab** to scan the current page's URL).
3. ⚙ settings: set **Backend URL** (defaults to the deployed Render URL) and an
   optional **API key**. The gear also shows a live backend health probe.
4. Right-click any link or selected text → **Check with CyberCheck** → desktop
   notification with the verdict.
5. On every page, links whose visible text claims one domain but point to another
   get a dashed red outline and a "why" tooltip — fully local, no network.
6. **Proactive protection (on by default):** every time you navigate to a new
   site, CyberCheck runs a fast local heuristic and — only if that looks
   suspicious — a backend check with a 2.5 s budget. If the verdict meets your
   threshold (High by default) the tab is redirected to `blocked.html` and the
   site never renders. From there you can go back, continue once, or always
   allow the site. Any error or timeout **fails open** (the site loads). Turn it
   off or loosen the threshold in ⚙.

Only the backend URL / API key are persisted. Nothing you check is stored;
passwords are SHA-1-prefixed before anything leaves the process.

---

## Privacy

- `check_breach` sends only the first 5 hex chars of `SHA-1(value)` to the HIBP
  range API (k-anonymity). `details.bytes_of_raw_value_sent` is always `0`.
- `check_password_strength` returns only derived metrics — never the password.
- The response cache is keyed by `SHA-256(salt + type + value)`, never the raw value.
- The backend never logs the `value` field.

---

## Deploy

See [DEPLOY.md](DEPLOY.md). Short version for Render:
push this folder as a repo → New Blueprint (reads `render.yaml`) → add env vars →
point the extension's Backend URL at the `*.onrender.com` URL. A `/health` ping
every ~10 min (cron-job.org) keeps the free instance awake.

---

## License

MIT — see [LICENSE](LICENSE).
