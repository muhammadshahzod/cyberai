"use strict";

/*
 * CyberUzCheck service worker
 *  1. Proactive protection: before a new site opens, run a fast LOCAL check;
 *     for anything suspicious, ask the backend (2.5s budget). If the verdict is
 *     "high" (or >= the user's threshold) the tab is redirected to blocked.html
 *     and the site never renders. Any error/timeout = fail OPEN (site loads).
 *  2. Right-click a link / selection -> "Check with CyberUzCheck" -> notification.
 *  3. Relays check requests from the popup / content script.
 */

const DEFAULT_BACKEND = "https://cyberuzcheck-backend.onrender.com";
const BACKEND_BUDGET_MS = 2500;
const VERDICT_TTL_MS = 60 * 60 * 1000; // 1h

// Never-check set (fast path for the obvious giants).
const TOP_SAFE = new Set([
  "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
  "whatsapp.com", "wikipedia.org", "amazon.com", "apple.com", "microsoft.com",
  "live.com", "office.com", "bing.com", "linkedin.com", "x.com", "twitter.com",
  "reddit.com", "netflix.com", "spotify.com", "github.com", "gitlab.com",
  "stackoverflow.com", "cloudflare.com", "mozilla.org", "yahoo.com",
  "yandex.ru", "mail.ru", "telegram.org", "chatgpt.com", "openai.com",
  "anthropic.com", "claude.ai", "render.com", "onrender.com",
]);

const POPULAR = [
  "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
  "microsoft.com", "paypal.com", "netflix.com", "instagram.com", "linkedin.com",
  "bankofamerica.com", "wellsfargo.com", "chase.com", "coinbase.com", "binance.com",
  "dropbox.com", "github.com", "whatsapp.com", "gmail.com", "outlook.com",
  "icloud.com", "steamcommunity.com", "telegram.org", "discord.com", "roblox.com",
];
const SUS_TLD = new Set(["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
  "click", "link", "work", "support", "loan", "review", "men", "download",
  "stream", "racing", "party", "date", "faith", "cricket", "rest", "cfd",
  "sbs", "quest", "bond", "monster", "lol", "country", "gdn", "kim"]);
const BRANDS = ["paypal", "apple", "icloud", "amazon", "microsoft", "office",
  "outlook", "google", "gmail", "facebook", "instagram", "whatsapp", "netflix",
  "bankofamerica", "wellsfargo", "chase", "coinbase", "binance", "dropbox",
  "github", "steam", "discord", "telegram", "dhl", "fedex", "ups"];
const DEHOMO = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s" };

/* ---------------- settings / storage ---------------- */

async function cfg() {
  const d = await chrome.storage.local.get(
    ["backendUrl", "apiKey", "protectionEnabled", "blockThreshold", "allowlist"]);
  return {
    backend: (d.backendUrl || DEFAULT_BACKEND).replace(/\/+$/, ""),
    apiKey: d.apiKey || "",
    protection: d.protectionEnabled !== false, // default ON
    threshold: d.blockThreshold || "high",     // "high" | "medium"
    allowlist: new Set(d.allowlist || []),
  };
}

// session-only "proceed anyway" set + verdict cache
const sessionAllow = new Set();
const verdictCache = new Map(); // host -> { risk, reasons, ts }

/* ---------------- helpers ---------------- */

function registrable(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  const last2 = p.slice(-2).join(".");
  const multi = new Set(["co.uk", "org.uk", "com.au", "co.jp", "co.nz", "com.br", "com.tr", "co.in"]);
  return multi.has(last2) ? p.slice(-3).join(".") : last2;
}

function lev(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++)
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
    prev = cur;
  }
  return prev[n];
}

function dehomo(s) { return s.replace(/[013457$]/g, (c) => DEHOMO[c] || c); }

// Fast local phishing heuristic. Returns {score, reasons[]}.
function localScan(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return { score: 0, reasons: [] }; }
  const host = u.hostname.toLowerCase();
  const reasons = [];
  let score = 0;

  if (u.protocol === "http:") { score += 2; reasons.push("Connection is plain HTTP, not HTTPS."); }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 3; reasons.push("Address is a raw IP, not a domain name."); }
  if (host.startsWith("xn--") || host.includes(".xn--")) { score += 2; reasons.push("Domain uses look-alike (punycode) characters."); }
  if ((u.username || u.password)) { score += 3; reasons.push("URL hides its real destination with '@'."); }

  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  if (SUS_TLD.has(tld)) { score += 2; reasons.push(`The .${tld} domain zone is heavily abused by scams.`); }
  if (labels.length >= 5) { score += 1; reasons.push("Unusually many sub-domains."); }
  if ((host.match(/-/g) || []).length >= 3) { score += 1; reasons.push("Many hyphens in the host name."); }

  const reg = registrable(host);
  const regLabel = reg.split(".")[0];
  for (const b of BRANDS) {
    if (host.includes(b) && !regLabel.includes(b)) {
      score += 3; reasons.push(`Uses the brand "${b}" but is not an official ${b} domain.`); break;
    }
  }
  const regN = dehomo(reg);
  for (const good of POPULAR) {
    const dR = lev(reg, good);
    if (dR === 0) break;
    const dN = lev(regN, good);
    if ((dR >= 1 && dR <= 2) || (regN !== reg && dN <= 2)) {
      score += 3; reasons.push(`Domain closely imitates ${good} (possible typosquatting).`); break;
    }
  }
  for (const t of ["secure", "login", "verify", "account", "update", "confirm", "wallet", "recover", "unlock"]) {
    if (host.includes(t)) { score += 1; reasons.push(`Host contains the bait word "${t}".`); break; }
  }
  return { score, reasons };
}

/* ---------------- backend ---------------- */

async function backendCheck(url, c) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), BACKEND_BUDGET_MS);
  try {
    const headers = { "Content-Type": "application/json" };
    if (c.apiKey) headers["X-API-Key"] = c.apiKey;
    const r = await fetch(c.backend + "/api/check", {
      method: "POST", headers, signal: ctrl.signal,
      body: JSON.stringify({ type: "url", value: url }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || r.status);
    return j; // {risk_level, summary, signals, ...}
  } finally {
    clearTimeout(timer);
  }
}

/* ---------------- the navigation guard ---------------- */

const RANK = { low: 0, unknown: 1, medium: 1, high: 2 };

async function guard(details) {
  if (details.frameId !== 0) return;                 // main frame only
  const url = details.url || "";
  if (!/^https?:\/\//i.test(url)) return;

  let c;
  try { c = await cfg(); } catch { return; }
  if (!c.protection) return;

  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch { return; }
  const reg = registrable(host);

  if (TOP_SAFE.has(reg) || c.allowlist.has(host) || c.allowlist.has(reg)) return;
  if (sessionAllow.has(host) || sessionAllow.has(url)) return;

  const cached = verdictCache.get(host);
  if (cached && Date.now() - cached.ts < VERDICT_TTL_MS) {
    if (RANK[cached.risk] >= RANK[c.threshold]) block(details.tabId, url, host, cached.risk, cached.reasons);
    return;
  }

  const local = localScan(url);
  const startedAt = Date.now();

  // Clear local hit -> block immediately, no network needed.
  if (local.score >= 5) {
    verdictCache.set(host, { risk: "high", reasons: local.reasons, ts: Date.now() });
    block(details.tabId, url, host, "high", local.reasons);
    return;
  }

  // Otherwise consult the backend, but never hold the user hostage.
  let verdict = null;
  try {
    verdict = await backendCheck(url, c);
  } catch {
    verdict = null; // fail OPEN
  }
  if (!verdict) {
    // remember the (weak) local read so we don't re-scan every click
    verdictCache.set(host, { risk: local.score >= 2 ? "medium" : "low", reasons: local.reasons, ts: Date.now() });
    return;
  }

  const risk = String(verdict.risk_level || "low").toLowerCase();
  const reasons = (verdict.signals && verdict.signals.length ? verdict.signals : local.reasons) || [];
  verdictCache.set(host, { risk, reasons, ts: Date.now() });

  if (RANK[risk] >= RANK[c.threshold] && Date.now() - startedAt < 8000) {
    // only redirect if the tab is still sitting on this URL
    try {
      const tab = await chrome.tabs.get(details.tabId);
      const cur = tab.pendingUrl || tab.url || "";
      if (cur === url || cur.startsWith(new URL(url).origin)) {
        block(details.tabId, url, host, risk, reasons);
      }
    } catch { /* tab gone */ }
  }
}

function block(tabId, url, host, risk, reasons) {
  const params = new URLSearchParams({ url, host, risk });
  chrome.storage.session.set({ ["block_" + tabId]: { url, host, risk, reasons } }).catch(() => {});
  chrome.tabs.update(tabId, { url: chrome.runtime.getURL("blocked.html") + "?" + params.toString() })
    .catch(() => {});
  chrome.notifications.create({
    type: "basic", iconUrl: "icon48.png",
    title: "CyberUzCheck blocked a site",
    message: `${host} looks ${risk.toUpperCase()} risk. Opened a safety page instead.`,
    priority: 2,
  });
}

chrome.webNavigation.onBeforeNavigate.addListener(guard);
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  if (d.transitionQualifiers && d.transitionQualifiers.includes("client_redirect")) guard(d);
  paintBadge(d.tabId, d.url);
});

/* ---------------- toolbar badge = current tab risk ---------------- */

const BADGE = {
  high:   { text: "!",  color: "#c1121f" },
  medium: { text: "?",  color: "#b7791f" },
  low:    { text: "",   color: "#1a7f37" },
  unknown:{ text: "",   color: "#6b7280" },
};

function paintBadge(tabId, url) {
  try {
    if (!/^https?:\/\//i.test(url || "")) { chrome.action.setBadgeText({ tabId, text: "" }); return; }
    const host = new URL(url).hostname.toLowerCase();
    const reg = registrable(host);
    let risk = "unknown";
    if (TOP_SAFE.has(reg)) risk = "low";
    const v = verdictCache.get(host);
    if (v) risk = v.risk;
    else {
      const local = localScan(url);
      if (local.score >= 5) risk = "high";
      else if (local.score >= 2) risk = "medium";
    }
    const b = BADGE[risk] || BADGE.unknown;
    chrome.action.setBadgeText({ tabId, text: b.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  } catch { /* ignore */ }
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    paintBadge(tabId, tab.url || tab.pendingUrl || "");
  } catch { /* ignore */ }
});

/* ---------------- "proceed anyway" bridge for blocked.html ---------------- */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.action === "proceed" && msg.url) {
      sessionAllow.add(msg.url);
      try { sessionAllow.add(new URL(msg.url).hostname.toLowerCase()); } catch {}
      const tabId = msg.tabId || (sender.tab && sender.tab.id);
      if (tabId) chrome.tabs.update(tabId, { url: msg.url });
      sendResponse({ ok: true });
    } else if (msg.action === "allowlist" && msg.host) {
      const { allowlist = [] } = await chrome.storage.local.get("allowlist");
      if (!allowlist.includes(msg.host)) allowlist.push(msg.host);
      await chrome.storage.local.set({ allowlist });
      sessionAllow.add(msg.host);
      if (msg.url) {
        const tabId = msg.tabId || (sender.tab && sender.tab.id);
        if (tabId) chrome.tabs.update(tabId, { url: msg.url });
      }
      sendResponse({ ok: true });
    } else if (msg.action === "check" && msg.value) {
      try {
        const c = await cfg();
        const data = await backendCheck(msg.value, c);
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: String(e.message || e) });
      }
    } else if (msg.action === "hostRisk" && msg.host) {
      const v = verdictCache.get(msg.host);
      const c2 = await cfg();
      sendResponse({
        ok: true,
        risk: v ? v.risk : null,
        reasons: v ? v.reasons : [],
        allowlisted: c2.allowlist.has(msg.host) || TOP_SAFE.has(registrable(msg.host)),
      });
    } else {
      sendResponse({ ok: false, error: "unknown action" });
    }
  })();
  return true; // async
});

/* ---------------- context menu ---------------- */

async function checkAndNotify(value, type) {
  try {
    const c = await cfg();
    const data = await backendCheck(value, c); // type is always url-ish here; backend detects
    const level = String(data.risk_level || "unknown").toUpperCase();
    await chrome.storage.local.set({ lastResult: { ...data, type: type || "url", at: Date.now() } });
    const { history = [] } = await chrome.storage.local.get("history");
    history.unshift({ type: type || "url", risk: data.risk_level, at: Date.now() });
    await chrome.storage.local.set({ history: history.slice(0, 15) });
    chrome.notifications.create({
      type: "basic", iconUrl: "icon48.png",
      title: `CyberUzCheck: ${level} RISK`,
      message: (data.summary || "Check complete.").slice(0, 240),
      priority: data.risk_level === "high" ? 2 : 0,
    });
  } catch (e) {
    chrome.notifications.create({
      type: "basic", iconUrl: "icon48.png",
      title: "CyberUzCheck: check failed", message: String(e.message || e),
    });
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  // Proactive protection is ON by default on first install; the user can toggle it.
  const cur = await chrome.storage.local.get(["protectionEnabled", "blockThreshold"]);
  const seed = {};
  if (cur.protectionEnabled === undefined) seed.protectionEnabled = true;
  if (cur.blockThreshold === undefined) seed.blockThreshold = "high";
  if (Object.keys(seed).length) await chrome.storage.local.set(seed);

  chrome.contextMenus.create({ id: "cc-link", title: "Check this link with CyberUzCheck", contexts: ["link"] });
  chrome.contextMenus.create({ id: "cc-sel", title: 'Check "%s" with CyberUzCheck', contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "cc-link" && info.linkUrl) checkAndNotify(info.linkUrl, "url");
  else if (info.menuItemId === "cc-sel" && info.selectionText) checkAndNotify(info.selectionText.trim(), null);
});
