"use strict";

/*
 * CyberUzCheck content script (local-first, page-safe):
 *  1. outline links whose visible text claims one domain but point to another
 *  2. warn before you type a password into a suspicious / unverified site
 */

(function () {
  const FLAG_CLASS = "__cybercheck_flag__";
  const MAX_LINKS = 800;
  let scanned = 0;

  const style = document.createElement("style");
  style.textContent = `
    .${FLAG_CLASS}{outline:2px dashed #c1121f !important;outline-offset:2px !important;border-radius:2px !important;cursor:help !important;}
    #__cybercheck_pwbar__{position:fixed;left:0;right:0;bottom:0;z-index:2147483647;
      background:#7f1d1d;color:#fff;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      padding:10px 14px;display:flex;gap:12px;align-items:center;box-shadow:0 -4px 20px rgba(0,0,0,.3);}
    #__cybercheck_pwbar__ b{font-weight:700;}
    #__cybercheck_pwbar__ button{margin-left:auto;background:#fff;color:#7f1d1d;border:0;border-radius:6px;
      padding:5px 12px;font-weight:700;cursor:pointer;}
  `;
  (document.head || document.documentElement).appendChild(style);

  /* ---------- A. link mismatch ---------- */

  function hostOf(url) {
    try { return new URL(url, location.href).hostname.toLowerCase(); } catch { return ""; }
  }
  function registrable(host) {
    const p = host.split(".");
    return p.length <= 2 ? host : p.slice(-2).join(".");
  }
  function linkReason(a) {
    const href = a.getAttribute("href") || "";
    if (!/^https?:/i.test(href) && !href.startsWith("//")) return null;
    const host = hostOf(href);
    if (!host) return null;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return "Link points to a raw IP address.";
    if (host.startsWith("xn--") || host.includes(".xn--")) return "Link host uses punycode (look-alike characters).";
    if ((href.split("://")[1] || "").split("/")[0].includes("@")) return "Link URL hides the real destination with '@'.";
    const text = (a.textContent || "").trim().toLowerCase();
    const m = text.match(/\b([a-z0-9-]+\.)+[a-z]{2,}\b/);
    if (m) {
      const claimed = registrable(m[0].replace(/^https?:\/\//, "").split("/")[0]);
      const actual = registrable(host);
      if (claimed && actual && claimed !== actual && !actual.endsWith("." + claimed)) {
        return `Link text says "${claimed}" but it actually goes to "${actual}".`;
      }
    }
    return null;
  }
  function scanLinks(root) {
    let links;
    try { links = (root || document).querySelectorAll("a[href]"); } catch { return; }
    for (const a of links) {
      if (scanned >= MAX_LINKS) return;
      if (a.dataset.cybercheckDone) continue;
      a.dataset.cybercheckDone = "1";
      scanned++;
      let why = null;
      try { why = linkReason(a); } catch { why = null; }
      if (why) {
        a.classList.add(FLAG_CLASS);
        const prev = a.getAttribute("title");
        a.setAttribute("title", (prev ? prev + " — " : "") + "⚠ CyberUzCheck: " + why);
      }
    }
  }

  /* ---------- B. password-entry guard ---------- */

  const SUS_TLD = new Set(["zip","mov","xyz","top","tk","ml","ga","cf","gq","click","link","work",
    "support","loan","review","men","download","stream","racing","party","date","cfd","sbs","quest",
    "bond","monster","lol","country","gdn","kim","rest"]);
  const BRANDS = ["paypal","apple","icloud","amazon","microsoft","office","outlook","google","gmail",
    "facebook","instagram","whatsapp","netflix","bank","wallet","coinbase","binance","dropbox",
    "github","steam","discord","telegram"];
  const DEHOMO = { "0":"o","1":"l","3":"e","4":"a","5":"s","7":"t","$":"s" };
  const POPULAR = ["google.com","facebook.com","amazon.com","apple.com","microsoft.com","paypal.com",
    "netflix.com","instagram.com","github.com","dropbox.com","coinbase.com","binance.com"];

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
  function localSiteScore() {
    const host = location.hostname.toLowerCase();
    let score = 0;
    if (location.protocol === "http:") score += 2;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) score += 3;
    if (host.startsWith("xn--") || host.includes(".xn--")) score += 2;
    const labels = host.split(".");
    if (SUS_TLD.has(labels[labels.length - 1])) score += 2;
    if (labels.length >= 5) score += 1;
    if ((host.match(/-/g) || []).length >= 3) score += 1;
    const reg = registrable(host);
    const regLabel = reg.split(".")[0];
    for (const b of BRANDS) if (host.includes(b) && !regLabel.includes(b)) { score += 3; break; }
    const regN = reg.replace(/[013457$]/g, (c) => DEHOMO[c] || c);
    for (const g of POPULAR) {
      const d = lev(reg, g);
      if (d === 0) break;
      if ((d >= 1 && d <= 2) || (regN !== reg && lev(regN, g) <= 2)) { score += 3; break; }
    }
    return score;
  }

  let pwWarned = false;
  function showPwBar(reasons) {
    if (pwWarned || document.getElementById("__cybercheck_pwbar__")) return;
    pwWarned = true;
    const bar = document.createElement("div");
    bar.id = "__cybercheck_pwbar__";
    const txt = document.createElement("span");
    txt.innerHTML = "<b>⚠ CyberUzCheck:</b> " +
      (reasons[0] || "This site is not verified. Be careful entering a password here.");
    const btn = document.createElement("button");
    btn.textContent = "Dismiss";
    btn.addEventListener("click", () => bar.remove());
    bar.append(txt, btn);
    document.body.appendChild(bar);
  }

  function armPasswordGuard() {
    const onFocus = async (e) => {
      const t = e.target;
      if (!t || t.tagName !== "INPUT" || t.type !== "password") return;
      const localScore = localSiteScore();
      let risky = localScore >= 3;
      let reasons = [];
      if (!risky) {
        try {
          const r = await chrome.runtime.sendMessage({ action: "hostRisk", host: location.hostname.toLowerCase() });
          if (r && r.ok && !r.allowlisted) {
            if (r.risk === "high" || r.risk === "medium") { risky = true; reasons = r.reasons || []; }
          }
        } catch { /* worker asleep - rely on local score */ }
      }
      if (risky) {
        if (!reasons.length) {
          reasons = [location.protocol === "http:"
            ? "This page is not using a secure (HTTPS) connection."
            : "This site looks suspicious and is not a known, verified domain."];
        }
        showPwBar(reasons);
      }
    };
    document.addEventListener("focusin", onFocus, true);
  }

  /* ---------- run ---------- */
  try {
    scanLinks(document);
    armPasswordGuard();
    const obs = new MutationObserver((muts) => {
      for (const mut of muts) for (const node of mut.addedNodes)
        if (node.nodeType === 1) scanLinks(node);
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => obs.disconnect(), 30000);
  } catch { /* never break the page */ }
})();
