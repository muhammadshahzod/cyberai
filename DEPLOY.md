# Deploying the CyberCheck backend

The backend is a normal WSGI app (`ai_extencion:app`), so it runs on any Python
host. Below: **Render** (easiest free option), then notes for alternatives.

---

## Option A — Render (recommended)

### 1. Put this folder in its own GitHub repo

Render deploys from a repo, and the app files must be at the repo root.

```bash
cd "cybercheck/cyberai"
rm -rf .git __pycache__          # start clean (there were nested git repos)
git init
git add .
git commit -m "CyberCheck backend"
# create an empty repo on github.com, then:
git remote add origin https://github.com/<you>/cybercheck-backend.git
git branch -M main
git push -u origin main
```

### 2. Create the service on Render

- render.com → **New +** → **Web Service** → connect the repo
- Render auto-detects `render.yaml`. If asked manually:
  - **Build command:** `pip install -r requirements.txt`
  - **Start command:** `gunicorn ai_extencion:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30`
  - **Instance type:** Free

### 3. Add environment variables (Render → your service → Environment)

| Key | Value |
|---|---|
| `AWS_REGION` | e.g. `us-west-2` |
| `AWS_ACCESS_KEY_ID` | your key |
| `AWS_SECRET_ACCESS_KEY` | your secret |
| `STRANDS_MODEL_ID` | e.g. `us.anthropic.claude-sonnet-4-20250514-v1:0` (optional) |
| `HIBP_API_KEY` | optional, enables email account-breach lookups |

Leave AWS vars unset to run in **direct mode** (tools still work, no AI summary).

### 4. Deploy

Render gives you a URL like `https://cybercheck-backend.onrender.com`.
Test it:

```bash
curl -s https://cybercheck-backend.onrender.com/health
curl -s https://cybercheck-backend.onrender.com/api/check \
  -H 'Content-Type: application/json' \
  -d '{"type":"password","value":"123456"}'
```

> **Free tier note:** the instance sleeps after ~15 min idle; the first request
> after that takes ~30-60 s to wake. Fine for a demo. Upgrade the plan or ping
> `/health` on a schedule if you need it always-hot.

---

## Point the Chrome extension at the deployed backend

1. Edit `manifest.json` → add your host to `host_permissions`:

   ```json
   "host_permissions": [
     "https://cybercheck-backend.onrender.com/*",
     "http://localhost:8000/*",
     "http://127.0.0.1:8000/*"
   ]
   ```

2. `chrome://extensions` → reload the CyberCheck card.
3. Open the popup → ⚙ → **Backend URL** = `https://cybercheck-backend.onrender.com` → **Save**.

Now the extension works from any machine, with your laptop off.

---

## Alternatives (same app, same start command)

- **Railway** (`railway.app`): New Project → Deploy from repo. It reads the
  `Procfile`. Add the same env vars. Gives `*.up.railway.app`.
- **Fly.io** (`fly launch`): pick Python, it writes a `fly.toml`; set secrets with
  `fly secrets set AWS_REGION=... AWS_ACCESS_KEY_ID=...`.
- **AWS App Runner / ECS / Lambda (via Mangum)**: closest to the "Agents for
  Humans" spirit since the agent already uses Bedrock; more setup than Render.

All of them need: `requirements.txt`, the start command
`gunicorn ai_extencion:app --bind 0.0.0.0:$PORT`, and the env vars above.

---

## Option B — Docker (App Runner / ECS / Cloud Run / Fly)

A `Dockerfile` is included. It runs `gunicorn ai_extencion:app` and respects `$PORT`.

```bash
docker build -t cybercheck .
docker run -p 8000:8000 --env-file .env cybercheck
```

- **AWS App Runner:** "Create service" → Source: container registry (push the image
  to ECR first) or "Source code" → it auto-detects the Dockerfile. Set the env
  vars in the console. Always-on, ~$5/mo.
- **Google Cloud Run:** `gcloud run deploy cybercheck --source . --allow-unauthenticated`
  — cold start ~1-2 s, generous free tier.

## Option C — AWS Lambda (serverless, free tier is huge)

```bash
pip install mangum        # add to requirements.txt for the deploy
```

Package `ai_extencion.py`, `lambda_handler.py`, and the deps; set the handler to
`lambda_handler.handler`; put it behind a **Function URL** or **API Gateway HTTP
API**. Set the same env vars as Lambda configuration. Note: the sqlite `/stats`
store is per-instance and ephemeral on Lambda — point `DB_PATH` at `/tmp` and
treat stats as best-effort, or swap it for DynamoDB.

## Environment variables (all optional)

| Var | Effect |
|---|---|
| `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | enables the Strands agent (`engine: "agent"`) |
| `STRANDS_MODEL_ID` | Bedrock model id |
| `GSB_API_KEY` | Google Safe Browsing lookups for URLs |
| `VT_API_KEY` | VirusTotal lookups for URLs and file hashes |
| `HIBP_API_KEY` | HaveIBeenPwned account-breach list for emails |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | push a message on every HIGH verdict |
| `API_KEY` | require header `X-API-Key` |
| `RATE_LIMIT_PER_MIN` | per-IP limit (default 120; 0 = off) |
| `CACHE_TTL_SECONDS` | response cache lifetime (default 900) |
| `DB_PATH` | sqlite file for `/stats`, feedback, monitors (default `cybercheck.db`) |

## Security reminders for a public deployment

- The endpoint is unauthenticated. For anything beyond a demo, add an API key
  header check in `check()` and a rate limit.
- Keep `debug` off (it already is unless `FLASK_DEBUG` is set).
- The privacy guarantees still hold: raw email/password never leave the process
  except the k-anonymity 5-char hash prefix (and the raw value is never logged).
