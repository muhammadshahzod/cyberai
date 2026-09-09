# CyberCheck — Personal Cybersecurity Checker Agent

An **AWS "Agents for Humans"** hackathon project built on the **Strands Agents SDK**.

CyberCheck is a single AI agent that helps a non-technical person answer one
question fast: **"Is this safe?"** — for an email address, a link, or a password.
A Chrome extension is the front door; a one-file Flask backend hosts one Strands
agent with three security tools.

Everything lives in this one folder.

---

## What it does

| You give it… | The agent calls… | You get back |
|---|---|---|
| an **email address** | `check_breach` | whether it shows up in known breaches (checked with k-anonymity) |
| a **link / URL** | `check_phishing` | a phishing-likelihood read from domain heuristics |
| a **password** | `check_password_strength` | an estimated crack time and how to make it stronger |

Every response is `{ "risk_level": "low"|"medium"|"high", "summary": "...", "details": {...} }`
— the `summary` is written by the agent in plain language; `details` is the raw
tool output for the curious.

---

## Architecture

```
┌──────────────────────────┐                ┌───────────────────────────────────────────────┐
│  Chrome extension (MV3)   │                │           Flask backend (ai_extencion.py)      │
│                          │   POST JSON     │                                               │
│  popup.html / popup.js   │ ──────────────► │  POST /api/check  { type, value }              │
│  • one input + Check      │                │        │                                      │
│  • renders risk + summary │ ◄────────────── │        ▼                                      │
│  • backend URL in storage │   JSON reply    │  Strands Agent (system prompt routes by type)  │
└──────────────────────────┘                │        │                                      │
                                            │        ├─ check_breach   ─► HIBP range API      │
                                            │        │                   (SHA-1 prefix only)  │
                                            │        ├─ check_phishing ─► local heuristics     │
                                            │        │                   (+ optional WHOIS)   │
                                            │        └─ check_password ─► zxcvbn (local only)  │
                                            │        │                                      │
                                            │        ▼                                      │
                                            │  aggregate severity + agent prose            │
                                            │  → { risk_level, summary, details }           │
                                            └───────────────────────────────────────────────┘
```

**Flow:** the extension POSTs `{type, value}` → the backend starts a per-request
findings collector and invokes the Strands agent → the agent's system prompt
selects exactly one tool by `type` → the tool runs, records a structured finding,
and returns it to the model → the model writes a short plain-language report →
the backend combines the agent's prose (`summary`) with the tool's structured
data (`details`) and the aggregated `risk_level`, and returns JSON.

**Graceful degradation:** if the Strands SDK or Bedrock access isn't configured,
the endpoint catches the failure and calls the matching tool directly, returning
a templated summary. The demo works with or without AWS.

---

## Folder contents (flat)

```
ai_extencion.py     # the whole backend: 3 tools + Strands agent + Flask endpoint
manifest.json       # Chrome extension, Manifest V3
popup.html          # extension popup markup
popup.js            # extension popup logic (fetch -> POST /api/check)
popup.css           # extension popup styles
icon16.png          # placeholder toolbar icons
icon48.png
icon128.png
make_icons.py       # regenerate the placeholder icons (standard library only)
requirements.txt
.env.example
.gitignore
LICENSE             # MIT
README.md
```

To load the extension, Chrome points at **this folder** — it ignores the `.py`,
`.md`, and `.txt` files and just reads `manifest.json`.

---

## Backend setup

```bash
cd cybercheck

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                  # then edit .env
```

**AWS credentials** (configured separately by you): the Strands agent uses
Amazon Bedrock. Provide credentials any standard way — `aws configure`,
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars, or an instance role — and
set `AWS_REGION` to a region where your chosen model is enabled. Make sure the
model (e.g. `us.anthropic.claude-sonnet-4-20250514-v1:0`) is enabled in the
Bedrock console. Override the model with `STRANDS_MODEL_ID`.

**Run:**

```bash
python ai_extencion.py               # serving on http://127.0.0.1:5000
```

**Smoke test:**

```bash
curl -s http://127.0.0.1:5000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"type":"url","value":"http://paypa1-secure-login.tk/verify"}' | python3 -m json.tool
```

---

## API reference

### `POST /api/check`

Request body:

```json
{ "type": "email" | "url" | "password", "value": "<string>" }
```

Response body:

```json
{
  "risk_level": "low" | "medium" | "high",
  "summary": "<plain-language report>",
  "details": { "...": "tool-specific fields" },
  "checks": ["check_phishing"],
  "engine": "agent" | "direct"
}
```

Errors: `400` with `{ "error": "..." }` for a missing/invalid `type` or empty `value`.
Other endpoints: `GET /` (service info), `GET /health`.

#### Example `details` per type

- **email → `check_breach`**: `sha1_prefix_sent`, `bytes_of_raw_value_sent`,
  `k_anonymity_hit_count`, `account_breach_lookup_enabled`, `account_breaches`.
- **url → `check_phishing`**: `host`, `registrable_domain`, `https`,
  `suspicious_tld`, `is_ip_literal`, `possible_typosquat_of`, `domain_age_days`,
  `heuristic_score`, `signals[]`.
- **password → `check_password_strength`**: `length`, `zxcvbn_score`,
  `guesses_log10`, `estimated_crack_time_*`, `warning`, `suggestions[]`.

---

## Privacy design

- **`check_breach` never sends the raw value.** It computes `SHA-1(value)` locally
  and sends only the **first 5 hex characters** of that hash to the
  [Pwned Passwords range API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
  (k-anonymity); suffix matching happens on the backend. `details.bytes_of_raw_value_sent`
  is always `0` for this path.
  - *Optional:* set `HIBP_API_KEY` to also query the account-breach API for emails.
    That call sends the address to HIBP over TLS — it's opt-in and off by default.
- **`check_password_strength` never logs, stores, or echoes the password.** Only
  derived metrics (length, zxcvbn score, crack-time estimates, tips) are returned.
- The backend **never logs the `value` field** — only the type, engine, risk
  level, and which tools ran.
- The agent's system prompt forbids repeating the raw email/URL/password.

---

## Chrome extension setup

1. Start the backend (above).
2. Open `chrome://extensions`, enable **Developer mode**.
3. **Load unpacked** → select this `cybercheck/` folder.
4. Click the CyberCheck toolbar icon. Paste an email, link, or password; pick a
   type or leave it on **Auto-detect**; click **Check**.
5. If your backend isn't on `http://localhost:5000`, open the ⚙ settings in the
   popup and set the backend URL. **Also** add that origin to `host_permissions`
   in `manifest.json` and reload the extension (MV3 requires it to be declared).

The extension only persists the backend URL (via `chrome.storage`). It never
stores anything you type.

Regenerate the placeholder icons any time with `python make_icons.py`.

---

## Tools in detail

**`check_breach(email)`** — k-anonymity credential-exposure check against the HIBP
range API, plus an optional account-breach lookup when `HIBP_API_KEY` is set.
Severity scales with hit count / breach sensitivity.

**`check_phishing(url)`** — weighted heuristics: missing HTTPS, raw-IP host,
`@` in the authority, punycode, abused TLDs, excessive sub-domains/hyphens, brand
keywords outside the registrable domain, Levenshtein typosquatting distance to a
list of popular domains, alarm keywords, and a best-effort WHOIS domain-age check
(`python-whois`, skipped if unavailable). Score ≥ 5 → high, 2–4 → medium, else low.

**`check_password_strength(password)`** — `zxcvbn` score (0–4), guess count, and
crack-time estimates for several attacker models, with the library's own
improvement tips. Falls back to a simple length/character-class estimate if
`zxcvbn` isn't installed.

---

## Limitations & future work

- Phishing detection is heuristic, not a threat feed — treat "low" as "no obvious
  red flags," not "verified safe."
- The default breach check matches leaked-*password* corpora; meaningful
  email-breach enumeration needs an HIBP API key.
- WHOIS is rate-limited and inconsistent across registrars.
- Next: reputation-feed lookups, a content script to flag links inline, response
  caching, and per-user history stored client-side only.

---

## License

MIT — see [LICENSE](LICENSE).
