/* FeatureMapper — Attack Surface Recon
 * Content script: walks the live DOM (incl. shadow roots + same-origin iframes)
 * as you browse and builds a nested "feature tree" (page > section > control),
 * mirroring the app's UI. Docked side panel, per-origin persistence.
 *
 * Features:
 *   - Feature tree with hover-highlight, tested checkboxes, MD/JSON/HTML export
 *   - Reveal Hidden (client-side gate bypass, reversible)
 *   - Unlock (remove paywall/overlays, restore scroll, reversible)
 *   - Role/session diffing (tag features by account, diff access)
 *   - JS intel extractor (endpoints, secrets, source maps, feature flags)
 *   - Parameter/input intel (per-field metadata + client-only-validation flag)
 *   - Shadow DOM + same-origin iframe traversal
 */
(() => {
  "use strict";
  if (window.__featureMapperLoaded) return;
  window.__featureMapperLoaded = true;

  const api = (typeof browser !== "undefined" ? browser : chrome);
  const ORIGIN = location.origin;
  const STORE_KEY = "fm:" + ORIGIN;
  const SETTINGS_KEY = "fm:settings";
  const INTEL_KEY = "fm:intel:" + ORIGIN;
  const HOST_ID = "fmap-host";

  /* ------------------------------------------------------------------ *
   *  Selectors                                                          *
   * ------------------------------------------------------------------ */
  const INTERACTIVE = [
    'a[href]', 'button', '[role="button"]', '[role="link"]', '[role="tab"]',
    '[role="menuitem"]', '[role="menuitemcheckbox"]', '[role="menuitemradio"]',
    '[role="option"]', '[role="switch"]', '[role="checkbox"]', '[role="radio"]',
    'input:not([type="hidden"])', 'select', 'textarea', 'summary',
    'label[for]', '[onclick]', '[class*="btn" i]', '[class*="button" i]'
  ].join(',');

  const STRONG_STRUCT = [
    'nav', 'header', 'footer', 'aside', 'form', 'dialog', 'main', 'table',
    '[role="navigation"]', '[role="tablist"]', '[role="menu"]', '[role="menubar"]',
    '[role="dialog"]', '[role="toolbar"]', '[role="search"]', '[role="form"]',
    '[class*="modal" i]', '[class*="dropdown" i]', '[class*="drawer" i]'
  ].join(',');
  const WEAK_STRUCT = [
    'section', '[role="region"]', '[role="group"]',
    '[class*="panel" i]', '[class*="menu" i]', '[class*="dialog" i]'
  ].join(',');

  const MAX_DEPTH = 3;

  /* ------------------------------------------------------------------ *
   *  JS-intel patterns (bounded, ReDoS-safe)                            *
   * ------------------------------------------------------------------ */
  const MAX_TEXT = 3000000;         // per-source scan cap
  const CAP = { endpoints: 3000, secrets: 400, flags: 600 };
  const SECRET_PATTERNS = [
    { label: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/g },
    { label: "Google API Key", re: /AIza[0-9A-Za-z\-_]{35}/g },
    { label: "Slack Token", re: /xox[baprs]-[0-9A-Za-z-]{10,72}/g },
    { label: "GitHub Token", re: /gh[pousr]_[0-9A-Za-z]{36,255}/g },
    { label: "Stripe Key", re: /[sprk]k_(?:live|test)_[0-9A-Za-z]{16,99}/g },
    { label: "Google OAuth", re: /ya29\.[0-9A-Za-z\-_]{20,}/g },
    { label: "JWT", re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}/g },
    { label: "Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
    { label: "Assigned secret", re: /(?:api[_-]?key|secret|token|password|passwd|auth[_-]?token|access[_-]?token|client[_-]?secret|bearer)["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-.]{8,80})["'`]/gi }
  ];
  const URL_RE = /https?:\/\/[A-Za-z0-9.\-]+(?::\d+)?(?:\/[A-Za-z0-9_\-.~%/?#\[\]@!$&'()*+,;=:]{0,300})?/g;
  const PATH_RE = /["'`](\/(?:api|v\d|graphql|gql|rest|internal|admin|users?|accounts?|auth|oauth|session|tokens?|upload|download|payments?|billing|invoices?|webhooks?|orders?|wallet|withdraw|deposit)[A-Za-z0-9_\-/.]{0,120})["'`]/gi;
  const SMAP_RE = /sourceMappingURL=([^\s'"*]+)/g;
  const FLAG_RE = /["'`]([A-Za-z0-9_.\-]{0,40}(?:feature|Feature|flag|Flag|enabled?|isBeta|experiment|rollout)[A-Za-z0-9_.\-]{0,40})["'`]/g;
  const OVERLAY_NAME = /overlay|backdrop|modal|paywall|gate|subscribe|premium|signup|register|login-?wall|popup|mask|scrim/i;

  /* ------------------------------------------------------------------ *
   *  In-memory model + state                                            *
   * ------------------------------------------------------------------ */
  let seq = Date.now();
  const uid = () => (seq++).toString(36);

  const byId = new Map();
  const sigIndex = new Map();
  const liveEl = new Map();
  const elSeen = new WeakMap();
  const contSeen = new WeakMap();
  const collapsed = new Set();
  const observedRoots = new WeakSet();

  let root = null;
  let currentPageId = null;
  let scanning = true;
  let panelOpen = false;
  let view = "tree";           // "tree" | "intel"
  let searchTerm = "";
  let currentRole = "anon";    // role/session tag applied to newly-seen features
  let diffMode = "";           // "" | "only:<role>"
  let intel = null;            // { scanning?, secrets[], endpoints[], sourcemaps[], flags[], ts, sources }

  // Reveal state
  let revealed = false;
  const undoStack = [];
  const forcedEls = new Set();
  let recordedNames = new WeakMap();

  // Unlock state
  let unlocked = false;
  const unlockUndo = [];
  const unlockEls = new Set();
  let unlockStyled = new WeakSet();

  /* ------------------------------------------------------------------ *
   *  Cross-root helpers (shadow DOM / iframes)                          *
   * ------------------------------------------------------------------ */
  function viewOf(el) { const d = el.ownerDocument; return (d && d.defaultView) || window; }
  function computedStyle(el) {
    try { return viewOf(el).getComputedStyle(el); }
    catch (e) { try { return getComputedStyle(el); } catch (_) { return null; } }
  }
  function parentAcross(el) {
    if (el.parentElement) return el.parentElement;
    const r = el.getRootNode && el.getRootNode();
    if (r && r instanceof ShadowRoot) return r.host || null;
    if (r && r.nodeType === 9 && r.defaultView) {
      try { return r.defaultView.frameElement || null; } catch (e) { return null; }
    }
    return null;
  }
  function inOurPanel(el) {
    const r = el.getRootNode && el.getRootNode();
    return !!(r && r instanceof ShadowRoot && r.host && r.host.id === HOST_ID);
  }

  /* ------------------------------------------------------------------ *
   *  Labelling / classification                                         *
   * ------------------------------------------------------------------ */
  function clean(s) { return (s || "").replace(/\s+/g, " ").trim(); }

  function labelText(el) {
    let t = clean(el.getAttribute("aria-label"));
    if (!t) {
      const lb = el.getAttribute("aria-labelledby");
      if (lb) { const r = (el.ownerDocument || document).getElementById(lb); if (r) t = clean(r.innerText); }
    }
    if (!t) t = clean(el.innerText);
    if (!t) t = clean(el.getAttribute("placeholder"));
    if (!t) t = clean(el.getAttribute("title"));
    if (!t && "value" in el) t = clean(el.value);
    if (!t) { const img = el.querySelector && el.querySelector("img[alt]"); if (img) t = clean(img.alt); }
    if (!t) t = clean(el.getAttribute("name"));
    return t.slice(0, 70);
  }

  function typeOf(el) {
    const tag = el.tagName.toLowerCase();
    const role = (el.getAttribute("role") || "").toLowerCase();
    if (role === "tab") return "tab";
    if (role.startsWith("menuitem") || role === "option") return "menu-item";
    if (tag === "a") return "link";
    if (tag === "select") return "select";
    if (tag === "textarea") return "textarea";
    if (tag === "input") {
      const t = (el.getAttribute("type") || "text").toLowerCase();
      if (t === "checkbox") return "checkbox";
      if (t === "radio") return "radio";
      if (t === "submit" || t === "button") return "button";
      return "input:" + t;
    }
    if (role === "checkbox" || role === "switch") return "toggle";
    if (role === "radio") return "radio";
    return "button";
  }

  function hasName(c) {
    if (clean(c.getAttribute("aria-label"))) return true;
    if (c.getAttribute("aria-labelledby")) return true;
    return !!c.querySelector(":scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > h5, :scope > h6, :scope > legend, [role='heading']");
  }
  function isStructural(c) {
    if (!c.matches) return false;
    if (c.matches(STRONG_STRUCT)) return true;
    if (c.matches(WEAK_STRUCT)) return hasName(c);
    return false;
  }
  function containerType(c) {
    const role = (c.getAttribute("role") || "").toLowerCase();
    const tag = c.tagName.toLowerCase();
    const cls = c.className && c.className.toString ? c.className.toString() : "";
    if (tag === "nav" || role === "navigation") return "nav";
    if (tag === "form" || role === "form" || role === "search") return "form";
    if (tag === "dialog" || role === "dialog" || /modal|dialog/i.test(cls)) return "dialog";
    if (role === "tablist") return "tabs";
    if (role === "menu" || role === "menubar" || /dropdown|(^|[^a-z])menu/i.test(cls)) return "menu";
    if (tag === "header") return "header";
    if (tag === "footer") return "footer";
    if (tag === "aside" || /drawer|sidebar/i.test(cls)) return "sidebar";
    if (tag === "table") return "table";
    if (tag === "main") return "main";
    return "section";
  }
  const TYPE_DEFAULT_NAME = {
    nav: "Navigation", form: "Form", dialog: "Dialog", tabs: "Tabs",
    menu: "Menu", header: "Header", footer: "Footer", sidebar: "Sidebar",
    table: "Table", main: "Main", section: "Section"
  };
  function containerName(c) {
    let t = clean(c.getAttribute("aria-label"));
    if (!t) {
      const lb = c.getAttribute("aria-labelledby");
      if (lb) { const r = (c.ownerDocument || document).getElementById(lb); if (r) t = clean(r.innerText); }
    }
    if (!t) {
      const h = c.querySelector(":scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > h5, :scope > h6, :scope > legend, [role='heading']");
      if (h) t = clean(h.innerText);
    }
    if (!t) {
      const ti = c.querySelector('[class*="title" i], [class*="heading" i]');
      if (ti && ti.innerText && ti.innerText.length < 60) t = clean(ti.innerText);
    }
    t = t.slice(0, 50);
    if (!t) t = TYPE_DEFAULT_NAME[containerType(c)] || "Section";
    return t;
  }
  function containerSig(c) {
    return "c|" + (c.id || "") + "|" + containerType(c) + "|" + containerName(c);
  }

  // Feature 5: per-field metadata
  function fieldMeta(el) {
    const tag = el.tagName.toLowerCase();
    if (tag !== "input" && tag !== "select" && tag !== "textarea") return null;
    const m = {
      tag,
      type: (el.getAttribute("type") || (tag === "select" ? "select" : tag === "textarea" ? "textarea" : "text")).toLowerCase(),
      name: el.getAttribute("name") || "",
      id: el.id || "",
      placeholder: el.getAttribute("placeholder") || "",
      required: el.hasAttribute("required"),
      pattern: el.getAttribute("pattern") || "",
      maxlength: el.getAttribute("maxlength") || "",
      minlength: el.getAttribute("minlength") || "",
      min: el.getAttribute("min") || "",
      max: el.getAttribute("max") || "",
      autocomplete: el.getAttribute("autocomplete") || ""
    };
    m.clientValidated = !!(m.required || m.pattern || m.maxlength || m.minlength || m.min || m.max);
    return m;
  }

  /* ------------------------------------------------------------------ *
   *  Visibility / interest gate                                         *
   * ------------------------------------------------------------------ */
  function isVisible(el) {
    if (!el.getBoundingClientRect) return false;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return false;
    const s = computedStyle(el);
    if (!s) return true;
    return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  }
  function isInteresting(el) {
    const tag = el.tagName.toLowerCase();
    if (tag === "input" || tag === "select" || tag === "textarea") return true;
    return labelText(el).length > 0;
  }

  /* ------------------------------------------------------------------ *
   *  Roles                                                              *
   * ------------------------------------------------------------------ */
  function markRole(nd) { if (!currentRole) return; (nd.roles || (nd.roles = {}))[currentRole] = 1; }
  function collectRoles(node, set) {
    if (node.roles) for (const k in node.roles) set.add(k);
    for (const c of node.children || []) collectRoles(c, set);
    return set;
  }
  function knownRoles() {
    const s = collectRoles(root || ensureRoot(), new Set());
    if (currentRole) s.add(currentRole);
    s.delete("");
    return [...s].sort();
  }

  /* ------------------------------------------------------------------ *
   *  Tree construction                                                  *
   * ------------------------------------------------------------------ */
  function ensureRoot() {
    if (root) return root;
    root = { id: "root", sig: "root", kind: "root", type: "root",
             label: ORIGIN, url: ORIGIN, count: 0, tested: false, children: [] };
    byId.set(root.id, root);
    return root;
  }
  function ensureChild(parent, sig, make) {
    const key = parent.id + " " + sig;
    const existing = sigIndex.get(key);
    if (existing) { const nd = byId.get(existing); if (nd) return nd; }
    const nd = make();
    nd.sig = sig;
    byId.set(nd.id, nd);
    parent.children.push(nd);
    sigIndex.set(key, nd.id);
    return nd;
  }
  function pagePath() {
    let p = location.pathname;
    if (location.hash && /^#\/?\w/.test(location.hash)) p += location.hash;
    return p || "/";
  }
  function pageLabel() {
    const h1 = document.querySelector("h1");
    return clean(document.title) || (h1 && clean(h1.innerText)) || pagePath();
  }
  function getPageNode() {
    ensureRoot();
    const path = pagePath();
    const nd = ensureChild(root, "p|" + path, () => ({
      id: uid(), kind: "page", type: "page", label: pageLabel(),
      url: location.href, path, count: 0, tested: false, children: []
    }));
    nd.url = location.href;
    if (!nd.label || nd.label === path) nd.label = pageLabel();
    markRole(nd);
    currentPageId = nd.id;
    liveEl.set(nd.id, document.body);
    return nd;
  }
  function structuralAncestors(el) {
    const chain = [];
    let n = parentAcross(el), depth = 0;
    const topBody = document.body, topHtml = document.documentElement;
    while (n && n !== topBody && n !== topHtml && depth < 80) {
      if (isStructural(n)) chain.unshift(n);
      n = parentAcross(n); depth++;
    }
    return chain.slice(-MAX_DEPTH);
  }
  function ensureContainerNode(c, parent) {
    if (contSeen.has(c)) { const nd = byId.get(contSeen.get(c)); if (nd) { markRole(nd); return nd; } }
    const nd = ensureChild(parent, containerSig(c), () => ({
      id: uid(), kind: "section", type: containerType(c),
      label: containerName(c), url: "", count: 0, tested: false, children: []
    }));
    if (c.tagName === "FORM" && !nd.form) {
      nd.form = { action: c.getAttribute("action") || "", method: (c.getAttribute("method") || "get").toLowerCase(), enctype: c.getAttribute("enctype") || "" };
    }
    markRole(nd);
    contSeen.set(c, nd.id);
    liveEl.set(nd.id, c);
    return nd;
  }
  function insertInteractive(el) {
    if (!scanning) return;
    if (inOurPanel(el)) return;
    if (elSeen.has(el)) { const nd = byId.get(elSeen.get(el)); if (nd) markRole(nd); return; }
    if (!isInteresting(el) || !isVisible(el)) return;

    let parent = getPageNode();
    for (const c of structuralAncestors(el)) parent = ensureContainerNode(c, parent);

    const type = typeOf(el);
    const label = labelText(el) || "(" + type + ")";
    const nd = ensureChild(parent, "i|" + type + "|" + label, () => ({
      id: uid(), kind: "control", type, label,
      url: el.tagName === "A" ? el.href : "", count: 0, tested: false, children: []
    }));
    if (!nd.field) { const fm = fieldMeta(el); if (fm) nd.field = fm; }
    nd.count++;
    markRole(nd);
    elSeen.set(el, nd.id);
    liveEl.set(nd.id, el);
    markChanged();
  }

  /* ------------------------------------------------------------------ *
   *  Scanner (shadow DOM + same-origin iframes)                         *
   * ------------------------------------------------------------------ */
  function scanFrameEl(fr) {
    let doc = null;
    try { doc = fr.contentDocument; } catch (e) { doc = null; } // cross-origin -> null/throw
    if (!fr.__fmapHooked) {
      fr.__fmapHooked = true;
      fr.addEventListener("load", () => {
        try {
          const d = fr.contentDocument;
          if (d && d.documentElement) { observeRoot(d); scanTree(d); }
        } catch (e) { /* cross-origin */ }
      });
    }
    if (!doc || !doc.documentElement) return;
    observeRoot(doc);
    scanTree(doc);
  }
  function scanTree(node) {
    if (!node) return;
    let list;
    try { list = node.querySelectorAll(INTERACTIVE); } catch (e) { list = []; }
    for (const el of list) insertInteractive(el);
    if (node.nodeType === 1 && node.matches && node.matches(INTERACTIVE)) insertInteractive(node);

    let all;
    try { all = node.querySelectorAll("*"); } catch (e) { all = []; }
    for (const el of all) {
      const sr = el.shadowRoot;
      if (sr) { observeRoot(sr); scanTree(sr); }
      else { const tn = el.tagName; if (tn === "IFRAME" || tn === "FRAME") scanFrameEl(el); }
    }
    if (node.nodeType === 1) {
      if (node.shadowRoot) { observeRoot(node.shadowRoot); scanTree(node.shadowRoot); }
      const tn = node.tagName; if (tn === "IFRAME" || tn === "FRAME") scanFrameEl(node);
    }
  }
  function fullScan() { scanTree(document); }

  /* ------------------------------------------------------------------ *
   *  Persistence                                                        *
   * ------------------------------------------------------------------ */
  let saveTimer = null, renderTimer = null;
  function markChanged() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(save, 700);
    if (panelOpen && view === "tree") {
      if (renderTimer) clearTimeout(renderTimer);
      renderTimer = setTimeout(render, 250);
    }
  }
  function save() { try { api.storage.local.set({ [STORE_KEY]: root }); } catch (e) { /* noop */ } }
  function reindex(node) {
    byId.set(node.id, node);
    for (const ch of node.children || []) {
      if (ch.sig) sigIndex.set(node.id + " " + ch.sig, ch.id);
      reindex(ch);
    }
  }
  function load() {
    return new Promise((resolve) => {
      try {
        api.storage.local.get([STORE_KEY, SETTINGS_KEY, INTEL_KEY], (res) => {
          const stored = res && res[STORE_KEY];
          if (stored && stored.children) { root = stored; reindex(root); } else ensureRoot();
          const st = (res && res[SETTINGS_KEY]) || {};
          scanning = st.scanning !== false;
          if (st.currentRole) currentRole = st.currentRole;
          const it = res && res[INTEL_KEY];
          if (it && (it.secrets || it.endpoints)) intel = it;
          resolve();
        });
      } catch (e) { ensureRoot(); resolve(); }
    });
  }
  function saveSettings() { try { api.storage.local.set({ [SETTINGS_KEY]: { scanning, currentRole } }); } catch (e) { /* noop */ } }
  function saveIntel() { try { api.storage.local.set({ [INTEL_KEY]: intel }); } catch (e) { /* noop */ } }

  /* ------------------------------------------------------------------ *
   *  Observers & navigation                                             *
   * ------------------------------------------------------------------ */
  function observeRoot(rootNode) {
    if (!rootNode || observedRoots.has(rootNode)) return;
    observedRoots.add(rootNode);
    const target = rootNode.nodeType === 9 ? rootNode.documentElement : rootNode;
    if (!target) return;
    try {
      const obs = new MutationObserver((muts) => {
        if (!scanning) return;
        for (const m of muts) for (const n of m.addedNodes) if (n.nodeType === 1) scanTree(n);
      });
      obs.observe(target, { childList: true, subtree: true });
    } catch (e) { /* noop */ }
  }

  let clickTimer = null;
  function onUserAction() {
    if (clickTimer) clearTimeout(clickTimer);
    clickTimer = setTimeout(() => { fullScan(); if (revealed) forceReveal(); }, 180);
    setTimeout(() => { if (scanning) fullScan(); if (revealed) forceReveal(); }, 600);
  }

  let lastPath = pagePath();
  function checkNav() {
    const p = pagePath();
    if (p !== lastPath) { lastPath = p; getPageNode(); setTimeout(() => { fullScan(); if (revealed) forceReveal(); }, 400); markChanged(); }
  }
  function hookHistory() {
    const wrap = (fn) => function () { const r = fn.apply(this, arguments); setTimeout(checkNav, 0); return r; };
    history.pushState = wrap(history.pushState);
    history.replaceState = wrap(history.replaceState);
    window.addEventListener("popstate", checkNav);
    window.addEventListener("hashchange", checkNav);
  }

  /* ------------------------------------------------------------------ *
   *  Reveal hidden (client-side gate bypass)                            *
   * ------------------------------------------------------------------ */
  const VALIDATION_ATTRS = ["maxlength", "minlength", "pattern", "required", "min", "max", "step"];
  function injectRevealStyle() {
    if (document.getElementById("fmap-reveal-style")) return;
    const st = document.createElement("style");
    st.id = "fmap-reveal-style";
    st.textContent =
      '[data-fmap-forced]{display:revert !important;visibility:visible !important;' +
      'opacity:1 !important;pointer-events:auto !important;' +
      'max-height:none !important;max-width:none !important;' +
      'clip:auto !important;clip-path:none !important;}' +
      '.fmap-revealed{outline:1px dashed #f59e0b !important;outline-offset:-1px !important;}';
    (document.head || document.documentElement).appendChild(st);
  }
  function removeRevealStyle() { const st = document.getElementById("fmap-reveal-style"); if (st) st.remove(); }
  function snapshotAttr(el, name) {
    let set = recordedNames.get(el);
    if (!set) { set = new Set(); recordedNames.set(el, set); }
    if (set.has(name)) return;
    set.add(name);
    const had = el.hasAttribute(name);
    const val = had ? el.getAttribute(name) : null;
    undoStack.push(() => { if (had) el.setAttribute(name, val); else el.removeAttribute(name); });
  }
  function markForced(el) { if (!forcedEls.has(el)) { forcedEls.add(el); el.classList.add("fmap-revealed"); } }
  function revealElement(el) {
    if (el.nodeType !== 1 || el.id === HOST_ID) return;
    const tag = el.tagName.toLowerCase();
    if (el.hasAttribute("hidden")) { snapshotAttr(el, "hidden"); el.removeAttribute("hidden"); }
    if (el.getAttribute("aria-hidden") === "true") { snapshotAttr(el, "aria-hidden"); el.setAttribute("aria-hidden", "false"); }
    const cs = computedStyle(el);
    if (cs && (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity) === 0)) {
      if (!el.hasAttribute("data-fmap-forced")) { el.setAttribute("data-fmap-forced", ""); markForced(el); }
    }
    if (tag === "input" && (el.getAttribute("type") || "").toLowerCase() === "hidden") {
      snapshotAttr(el, "type"); el.setAttribute("type", "text"); markForced(el);
    }
    for (const a of ["disabled", "readonly"]) if (el.hasAttribute(a)) { snapshotAttr(el, a); el.removeAttribute(a); markForced(el); }
    if (el.getAttribute("aria-disabled") === "true") { snapshotAttr(el, "aria-disabled"); el.setAttribute("aria-disabled", "false"); }
    for (const a of VALIDATION_ATTRS) if (el.hasAttribute(a)) { snapshotAttr(el, a); el.removeAttribute(a); }
    if (tag === "form" && !el.hasAttribute("novalidate")) { snapshotAttr(el, "novalidate"); el.setAttribute("novalidate", ""); }
    if (tag === "img") {
      const ds = el.getAttribute("data-src") || el.getAttribute("data-lazy-src") || el.getAttribute("data-original");
      if (ds && el.getAttribute("src") !== ds) { snapshotAttr(el, "src"); el.setAttribute("src", ds); }
    }
  }
  function forceReveal() {
    injectRevealStyle();
    let all; try { all = document.querySelectorAll("*"); } catch (e) { all = []; }
    for (const el of all) revealElement(el);
    fullScan();
    markChanged();
    updateRevealBtn();
    return forcedEls.size;
  }
  function restoreReveal() {
    while (undoStack.length) { try { undoStack.pop()(); } catch (e) { /* noop */ } }
    forcedEls.forEach((el) => { el.classList.remove("fmap-revealed"); el.removeAttribute("data-fmap-forced"); });
    forcedEls.clear();
    recordedNames = new WeakMap();
    removeRevealStyle();
    updateRevealBtn();
  }
  function toggleReveal() { revealed = !revealed; if (revealed) forceReveal(); else restoreReveal(); }

  /* ------------------------------------------------------------------ *
   *  Unlock (paywall/overlay killer + scroll restore)                   *
   * ------------------------------------------------------------------ */
  function injectUnlockStyle() {
    if (document.getElementById("fmap-unlock-style")) return;
    const st = document.createElement("style");
    st.id = "fmap-unlock-style";
    st.textContent =
      "html.fmap-unlocked, body.fmap-unlocked{overflow:auto !important;position:static !important;}" +
      ".fmap-unlock-hidden{display:none !important;}";
    (document.head || document.documentElement).appendChild(st);
  }
  function recordUnlockStyle(el) {
    if (unlockStyled.has(el)) return;
    unlockStyled.add(el);
    const had = el.hasAttribute("style");
    const v = had ? el.getAttribute("style") : null;
    unlockUndo.push(() => { if (had) el.setAttribute("style", v); else el.removeAttribute("style"); });
  }
  function unlockPage() {
    injectUnlockStyle();
    document.documentElement.classList.add("fmap-unlocked");
    if (document.body) document.body.classList.add("fmap-unlocked");
    const vw = window.innerWidth, vh = window.innerHeight;
    let hidden = 0;
    let all; try { all = document.body ? document.body.querySelectorAll("*") : []; } catch (e) { all = []; }
    for (const el of all) {
      if (el.id === HOST_ID || inOurPanel(el)) continue;
      const cs = computedStyle(el); if (!cs) continue;
      const pos = cs.position;
      if (pos === "fixed" || pos === "absolute" || pos === "sticky") {
        const r = el.getBoundingClientRect();
        const big = r.width >= vw * 0.6 && r.height >= vh * 0.55;
        const z = parseInt(cs.zIndex, 10) || 0;
        const cls = el.className && el.className.toString ? el.className.toString() : "";
        const nameHit = OVERLAY_NAME.test(cls);
        const translucent = /rgba?\([^)]*,\s*0?\.\d+\s*\)/.test(cs.backgroundColor || "");
        const blurred = cs.backdropFilter && cs.backdropFilter !== "none";
        if ((big && (z >= 50 || nameHit || translucent || blurred)) || (nameHit && z >= 50)) {
          el.classList.add("fmap-unlock-hidden"); unlockEls.add(el); hidden++;
          continue;
        }
      }
      if (cs.filter && cs.filter.indexOf("blur") >= 0) { recordUnlockStyle(el); el.style.setProperty("filter", "none", "important"); }
    }
    markChanged();
    return hidden;
  }
  function restoreUnlock() {
    while (unlockUndo.length) { try { unlockUndo.pop()(); } catch (e) { /* noop */ } }
    unlockEls.forEach((el) => el.classList.remove("fmap-unlock-hidden"));
    unlockEls.clear();
    unlockStyled = new WeakSet();
    document.documentElement.classList.remove("fmap-unlocked");
    if (document.body) document.body.classList.remove("fmap-unlocked");
    const st = document.getElementById("fmap-unlock-style"); if (st) st.remove();
  }
  function toggleUnlock() { unlocked = !unlocked; if (unlocked) unlockPage(); else restoreUnlock(); updateUnlockBtn(); }

  /* ------------------------------------------------------------------ *
   *  JS intel extractor (endpoints / secrets / sourcemaps / flags)      *
   * ------------------------------------------------------------------ */
  function pushCapped(arr, val, cap) {
    if (arr.length >= cap) return false;
    arr.push(val); return true;
  }
  function runIntelRegex(text, src, acc, seen) {
    if (!text) return;
    for (const p of SECRET_PATTERNS) {
      p.re.lastIndex = 0;
      let m, guard = 0;
      while ((m = p.re.exec(text)) && guard++ < 5000) {
        const val = (m[1] || m[0]).slice(0, 120);
        const key = "s|" + p.label + "|" + val;
        if (seen.has(key)) continue; seen.add(key);
        pushCapped(acc.secrets, { label: p.label, value: val, src }, CAP.secrets);
      }
    }
    URL_RE.lastIndex = 0;
    let u, g1 = 0;
    while ((u = URL_RE.exec(text)) && g1++ < 20000) {
      const v = u[0].slice(0, 300);
      const key = "e|" + v;
      if (seen.has(key)) continue; seen.add(key);
      pushCapped(acc.endpoints, v, CAP.endpoints);
    }
    PATH_RE.lastIndex = 0;
    let pa, g2 = 0;
    while ((pa = PATH_RE.exec(text)) && g2++ < 20000) {
      const v = pa[1].slice(0, 160);
      const key = "e|" + v;
      if (seen.has(key)) continue; seen.add(key);
      pushCapped(acc.endpoints, v, CAP.endpoints);
    }
    SMAP_RE.lastIndex = 0;
    let sm, g3 = 0;
    while ((sm = SMAP_RE.exec(text)) && g3++ < 2000) {
      let v = sm[1].slice(0, 300);
      try { v = new URL(v, src && /^https?:/.test(src) ? src : location.href).href; } catch (e) { /* keep raw */ }
      const key = "m|" + v;
      if (seen.has(key)) continue; seen.add(key);
      acc.sourcemaps.push(v);
    }
    FLAG_RE.lastIndex = 0;
    let fl, g4 = 0;
    while ((fl = FLAG_RE.exec(text)) && g4++ < 20000) {
      const v = fl[1].slice(0, 80);
      if (!v || v.length < 4) continue;
      const key = "f|" + v;
      if (seen.has(key)) continue; seen.add(key);
      pushCapped(acc.flags, v, CAP.flags);
    }
  }
  async function scanIntel() {
    intel = { scanning: true, secrets: [], endpoints: [], sourcemaps: [], flags: [], sources: 0, ts: new Date().toISOString() };
    view = "intel"; setView("intel");
    const acc = { secrets: [], endpoints: [], sourcemaps: [], flags: [] };
    const seen = new Set();
    const texts = [];
    try { texts.push({ src: "(page HTML)", text: document.documentElement.outerHTML.slice(0, MAX_TEXT) }); } catch (e) { /* noop */ }
    const scripts = Array.from(document.scripts || []);
    const jobs = [];
    for (const s of scripts) {
      if (s.src) {
        acc.endpoints.length < CAP.endpoints && pushCapped(acc.endpoints, s.src, CAP.endpoints);
        seen.add("e|" + s.src);
        jobs.push(
          fetch(s.src, { credentials: "omit" })
            .then((r) => r.text())
            .then((t) => ({ src: s.src, text: t.slice(0, MAX_TEXT) }))
            .catch(() => ({ src: s.src, text: "", failed: true }))
        );
      } else if (s.textContent) {
        texts.push({ src: "(inline script)", text: s.textContent.slice(0, MAX_TEXT) });
      }
    }
    let fetched = [];
    try { fetched = await Promise.all(jobs); } catch (e) { fetched = []; }
    for (const f of fetched) if (f && f.text) texts.push(f);
    for (const t of texts) runIntelRegex(t.text, t.src, acc, seen);
    // dedup endpoints/flags/sourcemaps (secrets already deduped by key)
    intel = {
      scanning: false,
      secrets: acc.secrets,
      endpoints: [...new Set(acc.endpoints)].sort(),
      sourcemaps: [...new Set(acc.sourcemaps)].sort(),
      flags: [...new Set(acc.flags)].sort(),
      sources: texts.length,
      ts: new Date().toISOString()
    };
    saveIntel();
    updateIntelBtn();
    renderIntel();
  }

  /* ------------------------------------------------------------------ *
   *  Export: Markdown, JSON, HTML report                                *
   * ------------------------------------------------------------------ */
  function fieldTag(f) {
    if (!f) return "";
    const bits = [f.type];
    if (f.name) bits.push("name=" + f.name);
    if (f.required) bits.push("required");
    if (f.pattern) bits.push("pattern");
    if (f.maxlength) bits.push("maxlen=" + f.maxlength);
    if (f.clientValidated) bits.push("client-validated");
    return " {" + bits.join(", ") + "}";
  }
  function rolesTag(nd) { return nd.roles ? " [" + Object.keys(nd.roles).join(",") + "]" : ""; }

  function toMarkdown(node, depth, out) {
    if (node.kind !== "root") {
      const pad = "  ".repeat(Math.max(0, depth - 1));
      const box = node.tested ? "[x]" : "[ ]";
      const meta = node.kind === "control" ? " `" + node.type + "`" : "";
      const url = node.url ? " — " + node.url : "";
      const cnt = node.count > 1 ? " (×" + node.count + ")" : "";
      out.push(pad + "- " + box + " **" + node.label + "**" + meta + fieldTag(node.field) + rolesTag(node) + cnt + url);
    }
    for (const ch of node.children || []) toMarkdown(ch, depth + 1, out);
    return out;
  }
  function download(name, text, mime) {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name;
    (document.body || document.documentElement).appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }
  function fileBase() { return "featuremap-" + location.hostname.replace(/[^\w.-]/g, "_"); }
  function exportMd() {
    const lines = ["# Feature map — " + ORIGIN, "", "_Generated by FeatureMapper on " + new Date().toISOString() + "_", ""];
    toMarkdown(root, 0, lines);
    if (intel && !intel.scanning) {
      lines.push("", "## JS Intel", "");
      if (intel.secrets.length) { lines.push("### Secrets"); intel.secrets.forEach((s) => lines.push("- **" + s.label + "**: `" + s.value + "` — " + s.src)); lines.push(""); }
      if (intel.endpoints.length) { lines.push("### Endpoints"); intel.endpoints.forEach((e) => lines.push("- " + e)); lines.push(""); }
      if (intel.sourcemaps.length) { lines.push("### Source maps"); intel.sourcemaps.forEach((e) => lines.push("- " + e)); lines.push(""); }
      if (intel.flags.length) { lines.push("### Feature flags"); intel.flags.forEach((e) => lines.push("- " + e)); lines.push(""); }
    }
    download(fileBase() + ".md", lines.join("\n"), "text/markdown");
  }
  function exportJson() {
    const payload = { origin: ORIGIN, generated: new Date().toISOString(), tree: root, intel };
    download(fileBase() + ".json", JSON.stringify(payload, null, 2), "application/json");
  }
  function reportNodeHtml(node, out) {
    if (node.kind !== "root") {
      const cls = "r-" + node.kind;
      const badge = node.kind === "control" ? ' <span class="ty">' + escapeHtml(node.type) + "</span>" : "";
      const fld = node.field ? ' <span class="fld">' + escapeHtml(fieldTag(node.field).trim()) + "</span>" : "";
      const roles = node.roles ? " " + Object.keys(node.roles).map((r) => '<span class="role">' + escapeHtml(r) + "</span>").join("") : "";
      const chk = node.tested ? "☑" : "☐";
      const url = node.url ? ' <a href="' + escapeAttr(node.url) + '">' + escapeHtml(node.url.slice(0, 80)) + "</a>" : "";
      out.push('<li class="' + cls + '"><span class="chk">' + chk + "</span> <b>" + escapeHtml(node.label) + "</b>" + badge + fld + roles + url);
    }
    if (node.children && node.children.length) {
      out.push("<ul>");
      for (const ch of node.children) reportNodeHtml(ch, out);
      out.push("</ul>");
    }
    if (node.kind !== "root") out.push("</li>");
    return out;
  }
  function buildReport() {
    const s = countControls(root);
    const treeHtml = reportNodeHtml(root, []).join("");
    let intelHtml = "";
    if (intel && !intel.scanning) {
      const list = (arr, fmt) => arr.length ? "<ul>" + arr.map(fmt).join("") + "</ul>" : "<p class=muted>none</p>";
      intelHtml =
        "<h2>JS Intel</h2>" +
        "<h3>Secrets (" + intel.secrets.length + ")</h3>" +
        list(intel.secrets, (x) => "<li><b>" + escapeHtml(x.label) + "</b>: <code>" + escapeHtml(x.value) + "</code> <span class=muted>" + escapeHtml(x.src) + "</span></li>") +
        "<h3>Endpoints (" + intel.endpoints.length + ")</h3>" +
        list(intel.endpoints, (x) => "<li><code>" + escapeHtml(x) + "</code></li>") +
        "<h3>Source maps (" + intel.sourcemaps.length + ")</h3>" +
        list(intel.sourcemaps, (x) => "<li><code>" + escapeHtml(x) + "</code></li>") +
        "<h3>Feature flags (" + intel.flags.length + ")</h3>" +
        list(intel.flags, (x) => "<li><code>" + escapeHtml(x) + "</code></li>");
    }
    const css = "body{font:14px -apple-system,Segoe UI,Roboto,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#111}" +
      "h1{font-size:20px}h2{margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}" +
      "ul{list-style:none;padding-left:18px;border-left:1px dotted #ccc}li{margin:2px 0}" +
      ".r-page>b{color:#1d4ed8}.r-section>b{color:#b45309}.ty{font-size:11px;color:#6d28d9;border:1px solid #ddd;border-radius:4px;padding:0 4px}" +
      ".fld{font-size:11px;color:#0369a1}.role{font-size:10px;background:#eef;border-radius:4px;padding:0 4px;margin-left:2px}" +
      ".chk{color:#888}code{background:#f4f4f5;padding:1px 4px;border-radius:3px;font-size:12px;word-break:break-all}.muted{color:#888}" +
      ".sum{display:flex;gap:16px;margin:12px 0}.sum div{background:#f4f4f5;border-radius:8px;padding:8px 14px}";
    return "<!doctype html><html><head><meta charset=utf-8><title>FeatureMapper — " + escapeHtml(location.hostname) +
      "</title><style>" + css + "</style></head><body>" +
      "<h1>FeatureMapper recon — " + escapeHtml(ORIGIN) + "</h1>" +
      "<p class=muted>Generated " + escapeHtml(new Date().toISOString()) + " · roles seen: " + escapeHtml(knownRoles().join(", ") || "—") + "</p>" +
      '<div class="sum"><div><b>' + s.c + "</b> features</div><div><b>" + s.p + "</b> pages</div>" +
      "<div><b>" + (intel ? intel.secrets.length : 0) + "</b> secrets</div><div><b>" + (intel ? intel.endpoints.length : 0) + "</b> endpoints</div></div>" +
      "<h2>Feature tree</h2><ul>" + treeHtml + "</ul>" + intelHtml + "</body></html>";
  }
  function exportReport() { download(fileBase() + "-report.html", buildReport(), "text/html"); }

  /* ------------------------------------------------------------------ *
   *  UI (shadow-DOM side panel)                                         *
   * ------------------------------------------------------------------ */
  let hostEl, shadow, treeEl, intelEl, statEl, launcherEl;

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: -apple-system, Segoe UI, Roboto, sans-serif; }
    .launcher { position: fixed; right: 16px; bottom: 16px; z-index: 2147483646;
      width: 48px; height: 48px; border-radius: 50%; cursor: pointer; background: #6d28d9;
      color: #fff; display: flex; align-items: center; justify-content: center; font-size: 22px;
      box-shadow: 0 4px 14px rgba(0,0,0,.4); border: none; user-select: none; }
    .launcher .badge { position: absolute; top: -4px; right: -4px; background: #ef4444; color: #fff;
      font-size: 11px; min-width: 18px; height: 18px; border-radius: 9px; display: flex;
      align-items: center; justify-content: center; padding: 0 4px; }
    .panel { position: fixed; top: 0; right: 0; height: 100vh; width: 400px; z-index: 2147483647;
      background: #0f1117; color: #e5e7eb; display: flex; flex-direction: column;
      box-shadow: -6px 0 24px rgba(0,0,0,.5); font-size: 13px; border-left: 1px solid #232838; }
    .hdr { padding: 8px 10px; border-bottom: 1px solid #232838; display: flex; flex-direction: column; gap: 7px; }
    .hdr .row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .title { font-weight: 700; font-size: 13px; flex: 1; color: #c4b5fd; }
    .origin { font-size: 11px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .btn { background: #1b2030; color: #cbd5e1; border: 1px solid #2b3145; border-radius: 6px;
      padding: 4px 8px; cursor: pointer; font-size: 12px; }
    .btn:hover { background: #262c40; }
    .btn.primary { background: #6d28d9; border-color: #6d28d9; color: #fff; }
    .btn.warn { color: #fca5a5; }
    .tab { cursor: pointer; padding: 4px 10px; border-radius: 6px; font-size: 12px; color: #9ca3af; border: 1px solid transparent; }
    .tab.primary { background: #1b2030; color: #c4b5fd; border-color: #2b3145; }
    .sel, select { background: #161b28; border: 1px solid #2b3145; border-radius: 6px; color: #e5e7eb; font-size: 11px; padding: 2px 4px; }
    .rl { font-size: 11px; color: #9ca3af; display: flex; align-items: center; gap: 4px; }
    .search { width: 100%; padding: 6px 8px; background: #161b28; border: 1px solid #2b3145; border-radius: 6px; color: #e5e7eb; font-size: 12px; }
    .stat { font-size: 11px; color: #9ca3af; }
    .body { flex: 1; overflow: auto; }
    .tree { padding: 6px 4px 24px; }
    .intel { padding: 10px; }
    .node { display: flex; align-items: center; gap: 6px; padding: 2px 6px; border-radius: 5px; }
    .node:hover { background: #1a1f2e; }
    .node.qual { background: #2a1f0e; }
    .node .tw { width: 14px; text-align: center; color: #6b7280; cursor: pointer; user-select: none; }
    .node .lbl { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; }
    .node.page > .lbl { font-weight: 700; color: #93c5fd; }
    .node.section > .lbl { font-weight: 600; color: #fcd34d; }
    .node.control > .lbl { color: #d1d5db; }
    .badge2 { font-size: 10px; color: #8b5cf6; border: 1px solid #3b3252; border-radius: 4px; padding: 0 4px; }
    .fldb { font-size: 10px; color: #38bdf8; }
    .lock { font-size: 10px; }
    .rolec { font-size: 9px; background: #23283a; color: #a5b4fc; border-radius: 4px; padding: 0 3px; margin-left: 2px; }
    .cnt { font-size: 10px; color: #6b7280; }
    .node input[type=checkbox] { accent-color: #6d28d9; }
    .hide { display: none !important; }
    .empty { color: #6b7280; padding: 20px; text-align: center; font-size: 12px; }
    .isec { margin-bottom: 14px; }
    .isec h4 { margin: 0 0 6px; font-size: 12px; color: #c4b5fd; }
    .irow { display: flex; gap: 6px; align-items: baseline; padding: 2px 0; border-bottom: 1px solid #171c28; }
    .irow code { color: #e5e7eb; font-size: 11px; word-break: break-all; flex: 1; }
    .irow .tag { font-size: 10px; color: #fca5a5; }
    .cpy { cursor: pointer; color: #6b7280; font-size: 11px; }
    .cpy:hover { color: #c4b5fd; }
    .muted { color: #6b7280; font-size: 11px; }
  `;

  const TYPE_ICON = {
    page: "📄", nav: "🧭", form: "📝", dialog: "🪟", tabs: "🗂", menu: "☰",
    header: "▔", footer: "▁", sidebar: "▐", table: "▦", main: "▣", section: "▹",
    link: "🔗", button: "🔘", tab: "🔖", "menu-item": "•", select: "▾",
    textarea: "🗒", checkbox: "☑", toggle: "🎚", radio: "◉"
  };
  const icon = (t) => TYPE_ICON[t] || (t && t.startsWith("input") ? "⌨" : "•");

  function buildPanel() {
    hostEl = document.createElement("div");
    hostEl.id = HOST_ID;
    shadow = hostEl.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = CSS;
    shadow.appendChild(style);

    launcherEl = document.createElement("button");
    launcherEl.className = "launcher";
    launcherEl.innerHTML = '🎯<span class="badge" id="fmap-badge">0</span>';
    launcherEl.title = "Open FeatureMapper";
    launcherEl.addEventListener("click", togglePanel);
    shadow.appendChild(launcherEl);

    const panel = document.createElement("div");
    panel.className = "panel hide";
    panel.id = "fmap-panel";
    panel.innerHTML = `
      <div class="hdr">
        <div class="row">
          <span class="title">🎯 FeatureMapper</span>
          <button class="btn" data-act="reveal" title="Force-show hidden elements, enable disabled controls, strip client-side validation (reversible)">👁 Reveal</button>
          <button class="btn" data-act="unlock" title="Remove blocking overlays/paywalls and restore scrolling (reversible)">🧱 Unlock</button>
          <button class="btn" data-act="pause"></button>
          <button class="btn" data-act="close">✕</button>
        </div>
        <div class="origin" id="fmap-origin"></div>
        <div class="row">
          <span class="tab primary" data-view="tree">Tree</span>
          <span class="tab" data-view="intel">🔑 Intel</span>
          <span style="flex:1"></span>
          <span class="rl">Session <select id="fmap-role"></select></span>
        </div>
        <div class="row" id="fmap-diffrow">
          <select id="fmap-diff" class="sel"></select>
          <span style="flex:1"></span>
          <span class="stat" id="fmap-stat"></span>
        </div>
        <input class="search" placeholder="Filter features…" id="fmap-search"/>
        <div class="row">
          <button class="btn" data-act="collapse">Collapse</button>
          <span style="flex:1"></span>
          <button class="btn" data-act="report">📄 Report</button>
          <button class="btn" data-act="md">MD</button>
          <button class="btn" data-act="json">JSON</button>
          <button class="btn warn" data-act="clear">Clear</button>
        </div>
      </div>
      <div class="body">
        <div class="tree" id="fmap-tree"></div>
        <div class="intel hide" id="fmap-intel"></div>
      </div>`;
    shadow.appendChild(panel);

    treeEl = panel.querySelector("#fmap-tree");
    intelEl = panel.querySelector("#fmap-intel");
    statEl = panel.querySelector("#fmap-stat");
    panel.querySelector("#fmap-origin").textContent = ORIGIN;
    panel.querySelector("#fmap-search").addEventListener("input", (e) => { searchTerm = e.target.value.toLowerCase(); render(); });
    panel.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => setView(t.getAttribute("data-view"))));
    panel.querySelector("#fmap-role").addEventListener("change", onRoleChange);
    panel.querySelector("#fmap-diff").addEventListener("change", (e) => { diffMode = e.target.value; render(); });
    panel.addEventListener("click", onPanelClick);

    (document.body || document.documentElement).appendChild(hostEl);
    updatePauseBtn(); updateRevealBtn(); updateUnlockBtn(); updateIntelBtn(); refreshSelectors();
  }

  function updatePauseBtn() { const b = shadow && shadow.querySelector('[data-act="pause"]'); if (b) { b.textContent = scanning ? "⏸ Rec" : "▶ Paused"; b.classList.toggle("primary", scanning); } }
  function updateRevealBtn() { const b = shadow && shadow.querySelector('[data-act="reveal"]'); if (b) { b.textContent = revealed ? ("👁 Shown " + forcedEls.size) : "👁 Reveal"; b.classList.toggle("primary", revealed); } }
  function updateUnlockBtn() { const b = shadow && shadow.querySelector('[data-act="unlock"]'); if (b) { b.textContent = unlocked ? ("🧱 Locked " + unlockEls.size) : "🧱 Unlock"; b.classList.toggle("primary", unlocked); } }
  function updateIntelBtn() { const b = shadow && shadow.querySelector('[data-view="intel"]'); if (b) b.textContent = "🔑 Intel" + (intel && intel.secrets ? " (" + (intel.secrets.length + intel.endpoints.length) + ")" : ""); }

  function refreshSelectors() {
    if (!shadow) return;
    const roles = knownRoles();
    const rsel = shadow.querySelector("#fmap-role");
    if (rsel) {
      rsel.innerHTML = roles.map((r) => '<option value="' + escapeAttr(r) + '"' + (r === currentRole ? " selected" : "") + ">" + escapeHtml(r) + "</option>").join("") +
        '<option value="__add">＋ Add session…</option>';
    }
    const dsel = shadow.querySelector("#fmap-diff");
    if (dsel) {
      dsel.innerHTML = '<option value="">All roles</option>' +
        roles.map((r) => '<option value="only:' + escapeAttr(r) + '"' + ("only:" + r === diffMode ? " selected" : "") + ">Only " + escapeHtml(r) + " reached</option>").join("");
      dsel.value = diffMode;
    }
  }
  function onRoleChange(e) {
    const v = e.target.value;
    if (v === "__add") {
      const r = (prompt("Session/role label (e.g. admin, user, anon):") || "").trim();
      if (r) currentRole = r;
    } else currentRole = v;
    saveSettings(); refreshSelectors(); fullScan(); render();
  }

  function onPanelClick(e) {
    const act = e.target.getAttribute && e.target.getAttribute("data-act");
    if (!act) return;
    if (act === "close") togglePanel();
    else if (act === "md") exportMd();
    else if (act === "json") exportJson();
    else if (act === "report") exportReport();
    else if (act === "pause") { scanning = !scanning; saveSettings(); updatePauseBtn(); if (scanning) fullScan(); }
    else if (act === "reveal") toggleReveal();
    else if (act === "unlock") toggleUnlock();
    else if (act === "scanjs") scanIntel();
    else if (act === "collapse") { collapseAll(); render(); }
    else if (act === "clear") {
      if (confirm("Clear the feature map for " + ORIGIN + "?")) {
        root = null; byId.clear(); sigIndex.clear(); liveEl.clear(); collapsed.clear();
        ensureRoot(); getPageNode(); save(); refreshSelectors(); render();
      }
    }
  }

  function setView(v) {
    view = v;
    if (!shadow) return;
    treeEl.classList.toggle("hide", v !== "tree");
    intelEl.classList.toggle("hide", v !== "intel");
    shadow.querySelectorAll(".tab").forEach((x) => x.classList.toggle("primary", x.getAttribute("data-view") === v));
    if (v === "intel") renderIntel(); else render();
  }

  function collapseAll() { for (const [id, nd] of byId) if (nd.children && nd.children.length && nd.id !== currentPageId) collapsed.add(id); }

  function togglePanel() {
    if (!hostEl) injectPanel();
    panelOpen = !panelOpen;
    shadow.querySelector("#fmap-panel").classList.toggle("hide", !panelOpen);
    launcherEl.classList.toggle("hide", panelOpen);
    if (panelOpen) { refreshSelectors(); if (view === "intel") renderIntel(); else render(); }
  }

  function countControls(node, acc) {
    acc = acc || { c: 0, p: 0 };
    if (node.kind === "control") acc.c++;
    if (node.kind === "page") acc.p++;
    for (const ch of node.children || []) countControls(ch, acc);
    return acc;
  }

  function passDiff(node) {
    if (!diffMode) return true;
    if (diffMode.startsWith("only:")) {
      const r = diffMode.slice(5);
      return !!(node.roles && node.roles[r] && Object.keys(node.roles).length === 1);
    }
    return true;
  }
  function qualifies(node) {
    const s = !searchTerm || (node.label || "").toLowerCase().includes(searchTerm);
    return s && passDiff(node);
  }
  function subtreeVisible(node) {
    if (node.kind !== "root" && qualifies(node)) return true;
    return (node.children || []).some(subtreeVisible);
  }

  function renderNode(node, depth, out) {
    if (node.kind !== "root") {
      if (!subtreeVisible(node)) return;
      const isCollapsed = collapsed.has(node.id) && !searchTerm;
      const hasKids = node.children && node.children.length;
      const tw = hasKids ? (isCollapsed ? "▸" : "▾") : "·";
      const badge = node.kind === "control" ? `<span class="badge2">${escapeHtml(node.type)}</span>` : "";
      const fld = node.field ? `<span class="fldb">${escapeHtml(node.field.name || node.field.type)}</span>` : "";
      const lock = node.field && node.field.clientValidated ? `<span class="lock" title="client-side validation only">🔒</span>` : "";
      const roles = (node.roles && knownRolesCache.length > 1) ? Object.keys(node.roles).map((r) => `<span class="rolec">${escapeHtml(r)}</span>`).join("") : "";
      const cnt = node.count > 1 ? `<span class="cnt">×${node.count}</span>` : "";
      const qual = diffMode && qualifies(node) ? " qual" : "";
      out.push(
        `<div class="node ${node.kind}${qual}" style="padding-left:${depth * 12}px">` +
          `<span class="tw" data-tw="${node.id}">${tw}</span>` +
          `<input type="checkbox" data-chk="${node.id}" ${node.tested ? "checked" : ""}/>` +
          `<span class="lbl" data-go="${node.id}" title="${escapeAttr(node.label)}">${icon(node.type)} ${escapeHtml(node.label)}</span>` +
          badge + fld + lock + roles + cnt +
        `</div>`
      );
      if (isCollapsed) return;
    }
    for (const ch of node.children || []) renderNode(ch, depth + (node.kind === "root" ? 0 : 1), out);
  }

  function escapeHtml(s) { return (s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
  function escapeAttr(s) { return escapeHtml(s).replace(/"/g, "&quot;"); }

  let knownRolesCache = [];
  function render() {
    if (!panelOpen || !treeEl || view !== "tree") { updateBadgeSafe(); return; }
    ensureRoot();
    knownRolesCache = knownRoles();
    const out = [];
    renderNode(root, 0, out);
    treeEl.innerHTML = out.length ? out.join("") : '<div class="empty">Browse the app — features will appear here.</div>';
    const s = countControls(root);
    statEl.textContent = s.c + " features · " + s.p + " pages";
    updateBadge(s.c);

    treeEl.querySelectorAll("[data-tw]").forEach((el) => el.addEventListener("click", () => {
      const id = el.getAttribute("data-tw");
      if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id);
      render();
    }));
    treeEl.querySelectorAll("[data-chk]").forEach((el) => el.addEventListener("change", () => {
      const nd = byId.get(el.getAttribute("data-chk")); if (nd) { nd.tested = el.checked; save(); }
    }));
    treeEl.querySelectorAll("[data-go]").forEach((el) => {
      const id = el.getAttribute("data-go");
      el.addEventListener("mouseenter", () => highlight(id, true));
      el.addEventListener("mouseleave", () => highlight(id, false));
      el.addEventListener("click", () => scrollToEl(id));
    });
  }

  function renderIntel() {
    if (!intelEl) return;
    if (!intel) {
      intelEl.innerHTML = '<div class="empty"><button class="btn primary" data-act="scanjs">🔑 Scan JavaScript for endpoints & secrets</button>' +
        '<p class="muted">Fetches same-origin scripts + inline code and extracts URLs, API routes, hardcoded keys/tokens, source maps, and feature-flag names.</p></div>';
      return;
    }
    if (intel.scanning) { intelEl.innerHTML = '<div class="empty">Scanning JavaScript…</div>'; return; }
    const rows = (arr, fmt) => arr.length ? arr.map(fmt).join("") : '<p class="muted">none</p>';
    const cpy = (v) => `<span class="cpy" data-copy="${escapeAttr(v)}">copy</span>`;
    const html =
      `<div class="row" style="margin-bottom:8px"><button class="btn" data-act="scanjs">↻ Rescan</button>` +
      `<span style="flex:1"></span><span class="muted">${intel.sources} sources · ${escapeHtml(intel.ts)}</span></div>` +
      `<div class="isec"><h4>🔓 Secrets (${intel.secrets.length})</h4>` +
      rows(intel.secrets, (x) => `<div class="irow"><span class="tag">${escapeHtml(x.label)}</span><code>${escapeHtml(x.value)}</code>${cpy(x.value)}</div>`) + `</div>` +
      `<div class="isec"><h4>🌐 Endpoints (${intel.endpoints.length})</h4>` +
      rows(intel.endpoints.slice(0, 800), (x) => `<div class="irow"><code>${escapeHtml(x)}</code>${cpy(x)}</div>`) +
      (intel.endpoints.length > 800 ? `<p class="muted">…and ${intel.endpoints.length - 800} more (in export)</p>` : "") + `</div>` +
      `<div class="isec"><h4>🗺 Source maps (${intel.sourcemaps.length})</h4>` +
      rows(intel.sourcemaps, (x) => `<div class="irow"><code>${escapeHtml(x)}</code>${cpy(x)}</div>`) + `</div>` +
      `<div class="isec"><h4>🚩 Feature flags (${intel.flags.length})</h4>` +
      rows(intel.flags.slice(0, 400), (x) => `<div class="irow"><code>${escapeHtml(x)}</code>${cpy(x)}</div>`) + `</div>`;
    intelEl.innerHTML = html;
    intelEl.querySelectorAll(".cpy").forEach((el) => el.addEventListener("click", () => copyText(el.getAttribute("data-copy"))));
  }

  function copyText(t) {
    try { navigator.clipboard.writeText(t); return; } catch (e) { /* fallback */ }
    try {
      const ta = document.createElement("textarea");
      ta.value = t; ta.style.position = "fixed"; ta.style.opacity = "0";
      (document.body || document.documentElement).appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    } catch (e) { /* noop */ }
  }

  function updateBadge(n) { const b = shadow && shadow.querySelector("#fmap-badge"); if (b) b.textContent = n > 999 ? "999+" : String(n); }
  function updateBadgeSafe() { if (root) updateBadge(countControls(root).c); }

  let lastHi = null;
  function highlight(id, on) {
    const el = liveEl.get(id);
    if (lastHi && lastHi !== el) { lastHi.style.outline = ""; lastHi = null; }
    if (!el || !el.isConnected) return;
    if (on) { el.style.outline = "2px solid #a855f7"; el.style.outlineOffset = "1px"; lastHi = el; }
    else { el.style.outline = ""; lastHi = null; }
  }
  function scrollToEl(id) { const el = liveEl.get(id); if (el && el.isConnected) el.scrollIntoView({ behavior: "smooth", block: "center" }); }

  /* ------------------------------------------------------------------ *
   *  Toolbar-icon toggle                                                *
   * ------------------------------------------------------------------ */
  try { api.runtime.onMessage.addListener((msg) => { if (msg === "fm-toggle") togglePanel(); }); } catch (e) { /* noop */ }

  /* ------------------------------------------------------------------ *
   *  Boot                                                               *
   * ------------------------------------------------------------------ */
  function injectPanel() {
    if (hostEl) return;
    buildPanel();
    updateBadgeSafe();
    if (panelOpen) render();
  }
  async function init() {
    await load();
    ensureRoot();
    getPageNode();
    observeRoot(document);
    hookHistory();
    document.addEventListener("click", onUserAction, true);
    fullScan();
    setTimeout(fullScan, 1200);
    setTimeout(fullScan, 3000);
    if (document.readyState === "complete") setTimeout(injectPanel, 0);
    else window.addEventListener("load", () => setTimeout(injectPanel, 0), { once: true });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
