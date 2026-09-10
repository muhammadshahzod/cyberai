<div align="center">

# 🛡️ CyberUzCheck

**A personal cybersecurity agent for everyday people.**
Paste a link, an email address, a password, an email header, or a file hash —
get a calm, plain-language risk verdict. And dangerous sites are blocked
*before they open*.

Built for the **AWS "Agents for Humans"** hackathon on the
[Strands Agents SDK](https://strandsagents.com) + **Amazon Bedrock**.

</div>

---

## Why

Most people can't tell a real login page from a fake one, don't know whether their
password has leaked, and have never read an email header. Security tools exist, but
they speak jargon. CyberUzCheck is one assistant you can ask **"is this safe?"**
about almost anything, plus background protection for when you don't think to ask.

## Features

### The agent (5 tools, one endpoint)

| Input `type` | Tool | What you get |
|---|---|---|
| `url` | `check_phishing` | Google Safe Browsing + URLhaus + VirusTotal, **plus** heuristics: homoglyph / typosquatting distance to popular domains, punycode, brand names on the wrong domain, abused TLDs, raw-IP hosts, `@`-in-URL, and domain age via RDAP |
| `email` | `check_breach` | whether the address appears in leaked-credential corpora — via **k-anonymity** (only the first 5 chars of the SHA-1 hash are sent) + optional Have I Been Pwned account-breach list |
| `password` | `check_password_strength` (+ `check_breach`) | zxcvbn crack-time estimate, concrete fixes, and whether the exact string has leaked. The raw password is never logged, stored, or echoed |
| `headers` | `check_email_headers` | SPF / DKIM / DMARC results, `From` vs `Return-Path` vs `Reply-To` mismatch, and display-name brand impersonation |
| `hash` | `check_file_hash` | VirusTotal reputation for an MD5 / SHA-1 / SHA-256 file hash |

The agent picks the tool from the input type and writes a 2–4 sentence report a
non-technical person can act on. **No AWS credentials?** It falls back to calling
the tools directly (`engine: "direct"`) so the demo always works.

### The Chrome extension (Manifest V3)

- **Proactive site blocking** (on by default, one toggle to disable). Before a new
  site opens: a fast **local** heuristic runs, and *only if that looks suspicious*
  a backend check with a **2.5 s budget**. High risk → the tab is redirected to a
  safety page and the site never renders. **Any error or timeout fails open** — it
  can never lock you out of the web. Allowlist + verdict cache keep it quiet.
- **Password-entry warning bar** before you type a password into an unverified or
  suspicious site.
- **Toolbar badge** coloured by the current tab's risk (green / amber `?` / red `!`).
- **Right-click** a link or selection → *Check with CyberUzCheck*.
- **"Report this result as wrong"** → feeds `/api/feedback`.
- Recent-checks history, "Paste & check", keyboard shortcut, allowlist synced
  across devices.

### The backend extras

- Salted-hash **TTL cache** + per-IP **rate limiting** + optional `X-API-Key`.
- **`/stats`** dashboard (HTML + `?format=json`) from a small SQLite verdict store.
- Optional **Telegram alert** on every HIGH verdict.
- Weekly **email-breach monitor** endpoints.

## How it works

```
┌────────────────────────────┐                 ┌──────────────────────────────────────────────┐
│  Chrome extension (MV3)     │                 │        Flask backend (ai_extencion.py)        │
│                            │   POST JSON      │                                              │
│  popup  ── manual checks ──────────────────►  │  POST /api/check { type, value }              │
│  service worker            │                  │        │                                     │
│   • navigation guard  ─────────────────────►  │        ▼                                     │
│   • local pre-scan (0 net) │  ◄───────────────│  Strands Agent (Amazon Bedrock)              │
│   • risk badge             │   JSON verdict   │   routes by type → 1 of 5 @tool functions     │
│  content script            │                  │        │                                     │
│   • link-mismatch outline  │                  │        ├─ check_phishing → GSB · URLhaus ·     │
│   • password warning bar   │                  │        │                  VirusTotal · RDAP    │
│  blocked.html interstitial │                  │        ├─ check_breach → HIBP range (k-anon)   │
└────────────────────────────┘                  │        ├─ check_password_strength → zxcvbn     │
                                                │        ├─ check_email_headers → SPF/DKIM/DMARC │
                                                │        └─ check_file_hash → VirusTotal         │
                                                │        │                                     │
                                                │        ▼  aggregate → { risk_level, summary,  │
                                                │           signals[], details{} }             │
                                                │   + TTL cache · rate limit · SQLite · /stats  │
                                                └──────────────────────────────────────────────┘
```

## Quick start

### Backend

```bash
git clone https://github.com/muhammadshahzod/cyberai
cd cyberai

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python ai_extencion.py          # http://127.0.0.1:8000
```

```bash
curl -s localhost:8000/api/check -H 'Content-Type: application/json' \
  -d '{"type":"url","value":"http://paypa1-secure-login.tk/verify"}'
```

Add AWS credentials (`aws configure` or env vars) and enable a Claude model in the
[Bedrock console](https://console.aws.amazon.com/bedrock/) to turn on the AI agent
(`engine: "agent"`). Without them it runs in `direct` mode.

### Extension

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this folder (or run `sh pack.sh` and load
   `dist/cyberuzcheck-extension/`).
3. Popup → ⚙ → set **Backend URL** if you're not using the hosted one.

See [`INSTALL.md`](INSTALL.md) for sharing a build with others.

## Configuration

All environment variables are optional.

| Var | Effect |
|---|---|
| `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | enable the Strands agent |
| `STRANDS_MODEL_ID` | Bedrock model id (e.g. `us.anthropic.claude-3-5-sonnet-20241022-v2:0`) |
| `GSB_API_KEY` | Google Safe Browsing lookups |
| `VT_API_KEY` | VirusTotal lookups (URLs + file hashes) |
| `HIBP_API_KEY` | Have I Been Pwned account-breach list |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | push a message on every HIGH verdict |
| `API_KEY` | require `X-API-Key: <value>` on requests |
| `RATE_LIMIT_PER_MIN` | per-IP limit (default `120`, `0` = off) |
| `CACHE_TTL_SECONDS` | response cache lifetime (default `900`) |
| `DB_PATH` | SQLite file for stats/feedback/monitors (default `cybercheck.db`) |

## API

### `POST /api/check`

```jsonc
// request
{ "type": "email" | "url" | "password" | "headers" | "hash", "value": "<string>" }

// response
{
  "risk_level": "low" | "medium" | "high",
  "summary": "<plain-language report>",
  "signals": ["<why, line by line>"],
  "details": { /* tool-specific */ },
  "checks": ["check_phishing"],
  "engine": "agent" | "direct",
  "verdict_id": 42,
  "cached": false
}
```

| Method & path | Purpose |
|---|---|
| `GET /health` | status + which integrations are live |
| `GET /stats` | dashboard (HTML, or `?format=json`) |
| `POST /api/feedback` | `{ verdict_id, host, correct: false, note }` |
| `POST /api/monitor` | `{ email }` → weekly breach watch, returns a token |
| `GET /api/monitor?token=` | that watch's latest state |
| `POST /api/monitor/run` | re-check every watch (point a cron here) |

## Privacy

- **`check_breach` never sends the raw value.** It computes `SHA-1(value)` locally
  and sends only the **first 5 hex characters** to the Pwned Passwords range API
  (k-anonymity). `details.bytes_of_raw_value_sent` is always `0` for this path.
- **`check_password_strength` never logs, stores, or echoes the password** — only
  derived metrics.
- The backend **never logs the `value` field**. Cache and database keys are
  **salted hashes**, never the raw input.
- The extension only persists your settings and a short local history (type + risk,
  never the value).

## Deployment

The backend is a standard WSGI app (`ai_extencion:app`). A `Procfile`,
`render.yaml`, `Dockerfile`, and `lambda_handler.py` are included.
Full walkthrough (Render / Docker / Cloud Run / AWS Lambda) in
[`DEPLOY.md`](DEPLOY.md).

Live demo backend: `https://cyberuzcheck-backend.onrender.com`
(free tier — first request after ~15 min idle takes ~50 s;
[`.github/workflows/keepalive.yml`](.github/workflows/keepalive.yml) keeps it warm).

## Project structure

```
ai_extencion.py     entire backend: 5 tools + Strands agent + Flask API
manifest.json       Chrome extension (MV3)
background.js        service worker — navigation guard, badge, context menu
content.js           link-mismatch outline + password warning bar
popup.html/js/css    the popup UI
blocked.html/js      the "site blocked" interstitial
icon16/48/128.png    icons  ·  make_icons.py regenerates them
test_app.py          pytest suite (17 tests)
Dockerfile · Procfile · render.yaml · lambda_handler.py    deploy targets
pack.sh              build a shareable extension zip
DEPLOY.md · INSTALL.md
```

## Tech stack

Python · Flask · gunicorn · **AWS Strands Agents SDK** · **Amazon Bedrock** ·
SQLite · Chrome Extension (Manifest V3) · vanilla JS/HTML/CSS · zxcvbn ·
Have I Been Pwned (Pwned Passwords k-anonymity) · Google Safe Browsing ·
URLhaus (abuse.ch) · VirusTotal · RDAP · Docker · Render · GitHub Actions

## Roadmap

- [ ] Reduce permissions and ship an unlisted Chrome Web Store build
- [ ] Multi-language reports (starting with Uzbek)
- [ ] Community intelligence — shared verdicts across users
- [ ] Fully serverless backend on AWS Lambda / App Runner
- [ ] Firefox (AMO) build

## Contributing

Issues and PRs welcome. Run the tests before opening a PR:

```bash
pip install -r requirements.txt pytest
DB_PATH=/tmp/test.db pytest -q
```

## License & disclaimer

[MIT](LICENSE). CyberUzCheck is a best-effort heuristic aid, **not** a guarantee —
a "low" result means "no obvious red flags", not "verified safe". Always use your
own judgement.
