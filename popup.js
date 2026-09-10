"use strict";

const DEFAULT_BACKEND = "http://localhost:8000";
const $ = (id) => document.getElementById(id);

async function getBackend() {
  try {
    const { backendUrl } = await chrome.storage.local.get("backendUrl");
    return (backendUrl || DEFAULT_BACKEND).replace(/\/+$/, "");
  } catch {
    return DEFAULT_BACKEND;
  }
}

function detectType(raw) {
  const s = raw.trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return "email";
  if (/^https?:\/\//i.test(s)) return "url";
  if (!/\s/.test(s) && /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) return "url";
  return "password";
}

function maskField(type) {
  // Show a password field only when the user is checking a password.
  $("value").type = type === "password" ? "password" : "text";
}

async function init() {
  let stored = {};
  try {
    stored = await chrome.storage.local.get("backendUrl");
  } catch {
    /* storage unavailable - fall back to default */
  }
  $("backend-url").value = stored.backendUrl || DEFAULT_BACKEND;

  $("settings-toggle").addEventListener("click", () => {
    $("settings").hidden = !$("settings").hidden;
  });

  $("save-settings").addEventListener("click", async () => {
    const url = $("backend-url").value.trim() || DEFAULT_BACKEND;
    try {
      await chrome.storage.local.set({ backendUrl: url });
    } catch {
      /* ignore */
    }
    $("settings").hidden = true;
  });

  $("type").addEventListener("change", () => maskField($("type").value));

  $("use-tab").addEventListener("click", async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url && /^https?:/i.test(tab.url)) {
        $("value").value = tab.url;
        $("type").value = "url";
        maskField("url");
      }
    } catch {
      /* activeTab not granted yet - ignore */
    }
  });

  $("check").addEventListener("click", runCheck);
  $("value").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runCheck();
  });
}

async function runCheck() {
  const value = $("value").value.trim();
  $("error").hidden = true;
  $("result").hidden = true;

  if (!value) {
    showError("Enter something to check.");
    return;
  }

  let type = $("type").value;
  if (type === "auto") type = detectType(value);

  const btn = $("check");
  btn.disabled = true;
  btn.textContent = "Checking…";

  try {
    const base = await getBackend();
    const resp = await fetch(base + "/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, value }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || "HTTP " + resp.status);
    render(data);
  } catch (e) {
    showError("Could not complete the check: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Check";
  }
}

function render(data) {
  const level = String(data.risk_level || "unknown").toLowerCase();
  const badge = $("badge");
  badge.textContent = level.toUpperCase() + " RISK";
  badge.className = "badge " + level;

  $("summary").textContent = data.summary || "";
  $("details").textContent = JSON.stringify(data.details ?? {}, null, 2);
  $("result").hidden = false;
}

function showError(msg) {
  const el = $("error");
  el.textContent = msg;
  el.hidden = false;
}

document.addEventListener("DOMContentLoaded", init);
