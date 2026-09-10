"use strict";

// CyberCheck background service worker:
//  - right-click a link / selected text -> "Check with CyberCheck"
//  - runs the check against the backend and shows a notification
//  - stores the last result so the popup can render it

const DEFAULT_BACKEND = "https://cyberuzcheck-backend.onrender.com";

async function getBackend() {
  try {
    const { backendUrl } = await chrome.storage.local.get("backendUrl");
    return (backendUrl || DEFAULT_BACKEND).replace(/\/+$/, "");
  } catch {
    return DEFAULT_BACKEND;
  }
}

async function getApiKey() {
  try {
    const { apiKey } = await chrome.storage.local.get("apiKey");
    return apiKey || "";
  } catch {
    return "";
  }
}

function detectType(raw) {
  const s = (raw || "").trim();
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return "email";
  if (/^https?:\/\//i.test(s)) return "url";
  if (!/\s/.test(s) && /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) return "url";
  return "password";
}

async function runCheck(value, type) {
  const base = await getBackend();
  const apiKey = await getApiKey();
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  const resp = await fetch(base + "/api/check", {
    method: "POST",
    headers,
    body: JSON.stringify({ type, value }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || "HTTP " + resp.status);
  return data;
}

async function pushHistory(entry) {
  try {
    const { history = [] } = await chrome.storage.local.get("history");
    history.unshift(entry);
    await chrome.storage.local.set({ history: history.slice(0, 15) });
  } catch {
    /* ignore */
  }
}

const ICONS = { low: "icon48.png", medium: "icon48.png", high: "icon48.png" };

async function checkAndNotify(value, type) {
  const kind = type || detectType(value);
  try {
    const data = await runCheck(value, kind);
    const level = String(data.risk_level || "unknown").toUpperCase();
    await chrome.storage.local.set({ lastResult: { ...data, type: kind, at: Date.now() } });
    await pushHistory({ type: kind, risk: data.risk_level, at: Date.now() });
    chrome.notifications.create({
      type: "basic",
      iconUrl: ICONS[data.risk_level] || "icon48.png",
      title: `CyberCheck: ${level} RISK`,
      message: (data.summary || "").slice(0, 240) || "Check complete.",
      priority: data.risk_level === "high" ? 2 : 0,
    });
  } catch (e) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon48.png",
      title: "CyberCheck: check failed",
      message: String(e.message || e),
    });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "cybercheck-link",
    title: "Check this link with CyberCheck",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "cybercheck-selection",
    title: 'Check "%s" with CyberCheck',
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "cybercheck-link" && info.linkUrl) {
    checkAndNotify(info.linkUrl, "url");
  } else if (info.menuItemId === "cybercheck-selection" && info.selectionText) {
    checkAndNotify(info.selectionText.trim(), null);
  }
});

// Let the content script ask the worker to run a check (used for the page banner).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.action === "check" && msg.value) {
    runCheck(msg.value, msg.type || detectType(msg.value))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
    return true; // async
  }
});
