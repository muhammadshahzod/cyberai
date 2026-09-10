"use strict";

/*
 * CyberCheck content script - lightweight, 100% local, no network calls.
 * Outlines links whose *visible text* claims one domain but whose href points
 * somewhere else, plus raw-IP / punycode / "@" tricks. Hover shows why.
 */

(function () {
  const MAX_LINKS = 800;
  const FLAG_CLASS = "__cybercheck_flag__";
  let scanned = 0;

  const style = document.createElement("style");
  style.textContent =
    "." + FLAG_CLASS + "{outline:2px dashed #c1121f !important;outline-offset:2px !important;" +
    "border-radius:2px !important;cursor:help !important;}";
  (document.head || document.documentElement).appendChild(style);

  function hostOf(url) {
    try {
      return new URL(url, location.href).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function registrable(host) {
    const p = host.split(".");
    return p.length <= 2 ? host : p.slice(-2).join(".");
  }

  function reason(a) {
    const href = a.getAttribute("href") || "";
    if (!/^https?:/i.test(href) && !href.startsWith("//")) return null;

    const host = hostOf(href);
    if (!host) return null;

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return "Link points to a raw IP address.";
    if (host.startsWith("xn--") || host.includes(".xn--")) return "Link host uses punycode (look-alike characters).";
    if ((href.split("://")[1] || "").split("/")[0].includes("@")) return "Link URL hides the real destination with '@'.";

    // visible text claims a domain?
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

  function scan(root) {
    let links;
    try {
      links = (root || document).querySelectorAll("a[href]");
    } catch {
      return;
    }
    for (const a of links) {
      if (scanned >= MAX_LINKS) return;
      if (a.dataset.cybercheckDone) continue;
      a.dataset.cybercheckDone = "1";
      scanned++;
      let why = null;
      try {
        why = reason(a);
      } catch {
        why = null;
      }
      if (why) {
        a.classList.add(FLAG_CLASS);
        const prev = a.getAttribute("title");
        a.setAttribute("title", (prev ? prev + " — " : "") + "⚠ CyberCheck: " + why);
      }
    }
  }

  try {
    scan(document);
    const obs = new MutationObserver((muts) => {
      for (const mut of muts) {
        for (const node of mut.addedNodes) {
          if (node.nodeType === 1) scan(node);
        }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    // stop watching after 30s to stay cheap
    setTimeout(() => obs.disconnect(), 30000);
  } catch {
    /* never break the page */
  }
})();
