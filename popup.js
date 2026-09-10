"use strict";

const DEFAULT_BACKEND = "https://cyberuzcheck-backend.onrender.com";
const $ = (id) => document.getElementById(id);

/* ---------------- settings ---------------- */

async function store(obj) {
  try { await chrome.storage.local.set(obj); } catch { /* ignore */ }
}
async function load(keys) {
  try { return await chrome.storage.local.get(keys); } catch { return {}; }
}

async function getBackend() {
  const { backendUrl } = await load("backendUrl");
  return (backendUrl || DEFAULT_BACKEND).replace(/\/+$/, "");
}
async function getApiKey() {
  const { apiKey } = await load("apiKey");
  return apiKey || "";
}

/* ---------------- helpers ---------------- */

function detectType(raw) {
  const s = raw.trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return "email";
  if (/^https?:\/\//i.test(s)) return "url";
  if (!/\s/.test(s) && /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) return "url";
  return "password";
}

function maskField(type) {
  $("value").type = type === "password" ? "password" : "text";
}

function fmtAgo(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}

/* ---------------- rendering ---------------- */

function render(data) {
  const level = String(data.risk_level || "unknown").toLowerCase();
  $("result").className = "";
  $("result").classList.add(level);
  $("badge").textContent = level.toUpperCase() + " RISK";
  $("badge").className = "badge " + level;
  $("engine").textContent = data.engine === "agent" ? "AI summary" : "rule-based";
  $("summary").textContent = data.summary || "";

  const ul = $("signals");
  ul.innerHTML = "";
  const signals = Array.isArray(data.signals) ? data.signals : [];
  if (signals.length === 0) {
    const li = document.createElement("li");
    li.className = "ok";
    li.textContent = "No specific warning signals.";
    ul.appendChild(li);
  } else {
    for (const s of signals) {
      const li = document.createElement("li");
      const low = s.toLowerCase();
      if (low.startsWith("no ") || low.includes("not found") || low.includes("no match")) li.className = "ok";
      else if (low.includes("add ") || low.includes("use ") || low.includes("avoid ") || low.includes("uncommon")) li.className = "tip";
      li.textContent = s;
      ul.appendChild(li);
    }
  }

  $("details").textContent = JSON.stringify(data.details ?? {}, null, 2);
  $("result").hidden = false;
  $("error").hidden = true;
}

async function renderHistory() {
  const { history = [] } = await load("history");
  const wrap = $("history-wrap");
  const ul = $("history");
  ul.innerHTML = "";
  if (!history.length) { wrap.hidden = true; return; }
  wrap.hidden = false;
  for (const h of history.slice(0, 8)) {
    const li = document.createElement("li");
    const lvl = String(h.risk || "unknown").toLowerCase();
    li.innerHTML =
      `<span>${h.type}</span>` +
      `<span><span class="pill ${lvl}">${lvl.toUpperCase()}</span> &nbsp;${fmtAgo(h.at)}</span>`;
    ul.appendChild(li);
  }
}

async function pushHistory(type, risk) {
  const { history = [] } = await load("history");
  history.unshift({ type, risk, at: Date.now() });
  await store({ history: history.slice(0, 15) });
  renderHistory();
}

/* ---------------- the check ---------------- */

let checking = false;

async function runCheck() {
  if (checking) return;
  const value = $("value").value.trim();
  $("error").hidden = true;
  if (!value) { showError("Enter something to check."); return; }

  let type = $("type").value;
  if (type === "auto") type = detectType(value);

  checking = true;
  const btn = $("check");
  btn.disabled = true;
  btn.textContent = "Checking…";
  $("status").hidden = false;
  $("status").textContent = "Contacting backend…";

  const slowTimer = setTimeout(() => {
    $("status").textContent = "Backend is waking up (free tier) — this can take ~50s…";
  }, 3500);

  try {
    const base = await getBackend();
    const apiKey = await getApiKey();
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;

    const data = await fetchWithRetry(base + "/api/check", {
      method: "POST",
      headers,
      body: JSON.stringify({ type, value }),
    });

    render(data);
    pushHistory(type, data.risk_level);
    store({ lastResult: { ...data, type, at: Date.now() } });
  } catch (e) {
    showError("Could not complete the check: " + e.message);
  } finally {
    clearTimeout(slowTimer);
    checking = false;
    btn.disabled = false;
    btn.textContent = "Check";
    $("status").hidden = true;
  }
}

async function fetchWithRetry(url, opts, tries = 2) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      const resp = await fetch(url, opts);
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(data.error || "HTTP " + resp.status);
      return data;
    } catch (e) {
      lastErr = e;
      if (i < tries - 1) await new Promise((r) => setTimeout(r, 1500));
    }
  }
  throw lastErr;
}

function showError(msg) {
  $("error").textContent = msg;
  $("error").hidden = false;
  $("result").hidden = true;
}

/* ---------------- backend status probe ---------------- */

async function probeBackend() {
  const el = $("backend-status");
  el.textContent = "Checking backend…";
  try {
    const base = await getBackend();
    const r = await fetch(base + "/health", { method: "GET" });
    const j = await r.json();
    el.textContent = j.status === "ok"
      ? `● online · ${j.agent_configured ? "AI agent on" : "rule-based"}${j.safe_browsing ? " · Safe Browsing on" : ""}`
      : "● reachable but unhealthy";
  } catch {
    el.textContent = "● offline / unreachable";
  }
}

/* ---------------- init ---------------- */

async function init() {
  const { backendUrl, apiKey } = await load(["backendUrl", "apiKey"]);
  $("backend-url").value = backendUrl || DEFAULT_BACKEND;
  $("api-key").value = apiKey || "";

  $("settings-toggle").addEventListener("click", () => {
    const s = $("settings");
    s.hidden = !s.hidden;
    if (!s.hidden) probeBackend();
  });

  $("save-settings").addEventListener("click", async () => {
    await store({
      backendUrl: $("backend-url").value.trim() || DEFAULT_BACKEND,
      apiKey: $("api-key").value.trim(),
    });
    probeBackend();
  });

  $("type").addEventListener("change", () => maskField($("type").value));

  $("use-tab").addEventListener("click", async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url && /^https?:/i.test(tab.url)) {
        $("value").value = tab.url;
        $("type").value = "url";
        maskField("url");
        runCheck();
      } else {
        showError("This tab has no checkable URL.");
      }
    } catch {
      showError("Could not read the current tab.");
    }
  });

  $("check").addEventListener("click", runCheck);
  $("value").addEventListener("keydown", (e) => { if (e.key === "Enter") runCheck(); });

  $("clear-history").addEventListener("click", async () => {
    await store({ history: [] });
    renderHistory();
  });

  renderHistory();

  // If a context-menu / notification check just ran, show its result.
  const { lastResult } = await load("lastResult");
  if (lastResult && Date.now() - lastResult.at < 5 * 60 * 1000) {
    render(lastResult);
  }
}

document.addEventListener("DOMContentLoaded", init);
