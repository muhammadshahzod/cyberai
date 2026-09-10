"use strict";

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const host = params.get("host") || "this site";
const risk = (params.get("risk") || "high").toUpperCase();

document.getElementById("host").textContent = host;
document.getElementById("risk").textContent = risk + " RISK";

(async () => {
  let reasons = [];
  let tabId = null;
  try {
    const tab = await chrome.tabs.getCurrent();
    tabId = tab && tab.id;
    if (tabId != null) {
      const store = await chrome.storage.session.get("block_" + tabId);
      const rec = store["block_" + tabId];
      if (rec && Array.isArray(rec.reasons)) reasons = rec.reasons;
    }
  } catch { /* ignore */ }

  const ul = document.getElementById("reasons");
  if (!reasons.length) {
    document.getElementById("why-lead").textContent =
      "This site matched a known-dangerous pattern or threat list.";
  }
  for (const r of reasons.slice(0, 8)) {
    const li = document.createElement("li");
    li.textContent = r;
    ul.appendChild(li);
  }

  const send = (action) =>
    chrome.runtime.sendMessage({ action, url: target, host, tabId });

  document.getElementById("back").addEventListener("click", async () => {
    if (history.length > 1) history.back();
    else if (tabId != null) chrome.tabs.remove(tabId);
    else location.href = "about:blank";
  });
  document.getElementById("once").addEventListener("click", () => send("proceed"));
  document.getElementById("always").addEventListener("click", () => send("allowlist"));
})();
