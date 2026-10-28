"use strict";
(() => {
  const root = document.getElementById("root");
  // A site with no favicon falls back to the globe glyph. Error events do not
  // bubble, so listen in the capture phase (inline onerror is blocked by our CSP).
  document.addEventListener("error", (e) => { if (e.target instanceof HTMLImageElement && e.target.classList.contains("fav")) e.target.remove(); }, true);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  function timeAgo(iso) {
    if (!iso) return "never";
    const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
  async function api(path, opts = {}) {
    const res = await fetch(path, { method: opts.method || "GET", headers: opts.body ? { "content-type": "application/json" } : {}, body: opts.body ? JSON.stringify(opts.body) : undefined });
    let data = {}; try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(data.error || `Error ${res.status}`);
    return data;
  }

  const STATE_LABEL = { new: "Not scanned", scanning: "Scanning…", secure: "No issues", at_risk: "Needs attention", exposed: "Exposed" };
  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  const KIND_LABEL = { repo: "White box", web: "Black box", artifact: "Forensics" };

  const ICON = {
    home: `<path d="M3 10.5 11 4l8 6.5V19a1 1 0 0 1-1 1h-4v-5H8v5H4a1 1 0 0 1-1-1z"/>`,
    assets: `<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="12" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="12" width="7" height="7" rx="1.5"/><rect x="12" y="12" width="7" height="7" rx="1.5"/>`,
    scans: `<circle cx="11" cy="11" r="3"/><path d="M11 2v3M11 17v3M2 11h3M17 11h3"/>`,
    reports: `<path d="M6 2h7l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/><path d="M13 2v5h5M8 12h6M8 16h6"/>`,
    gear: `<circle cx="11" cy="11" r="3"/><path d="M11 1.5v3M11 17.5v3M1.5 11h3M17.5 11h3M4 4l2 2M16 16l2 2M18 4l-2 2M6 16l-2 2"/>`,
    globe: `<circle cx="11" cy="11" r="9"/><path d="M2 11h18M11 2c3 3 3 15 0 18M11 2c-3 3-3 15 0 18"/>`,
    shield: `<path d="M11 2 3 5v6c0 5.3 3.4 9.2 8 10 4.6-.8 8-4.7 8-10V5z"/>`,
    alert: `<circle cx="11" cy="11" r="9"/><path d="M11 6v6M11 15.5v.5"/>`,
    radar: `<circle cx="11" cy="11" r="9"/><circle cx="11" cy="11" r="4"/><path d="M11 11 17 5"/>`,
    bell: `<path d="M6 9a5 5 0 0 1 10 0c0 5 2 6 2 6H4s2-1 2-6zM9 19a2 2 0 0 0 4 0"/>`,
    chev: `<path d="M8 5l6 6-6 6"/>`,
    code: `<path d="M8 7l-4 4 4 4M14 7l4 4-4 4"/>`,
    mask: `<path d="M3 7c4-2 12-2 16 0 0 6-3 9-8 9S3 13 3 7z"/><circle cx="8" cy="10" r="1.2"/><circle cx="14" cy="10" r="1.2"/>`,
    finger: `<path d="M7 11a4 4 0 0 1 8 0v3M9 11v4M13 11v5M5 12v2M17 12v2"/>`,
    db: `<ellipse cx="11" cy="5" rx="7" ry="2.6"/><path d="M4 5v12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V5"/><path d="M4 11c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6"/>`,
    server: `<rect x="3" y="4" width="16" height="6" rx="1.5"/><rect x="3" y="12" width="16" height="6" rx="1.5"/><path d="M6.5 7h.01M6.5 15h.01"/>`,
    key: `<circle cx="7.5" cy="14.5" r="4"/><path d="M10.5 11.5 19 3M15 7l3 3M17 5l2 2"/>`,
  };
  const ic = (n, w = 18) => `<svg width="${w}" height="${w}" viewBox="0 0 22 22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICON[n] || ""}</svg>`;

  function lockSvg(cls) {
    return `<svg class="${cls}" viewBox="0 0 120 140" aria-hidden="true">
      <ellipse class="glow" cx="60" cy="94" rx="54" ry="42"/>
      <path class="shackle" d="M38 58 V42 a22 22 0 0 1 44 0 V58"/>
      <rect class="body" x="26" y="58" width="68" height="62" rx="14"/>
      <circle class="keyhole" cx="60" cy="86" r="7"/><rect class="stem" x="57" y="88" width="6" height="16" rx="3"/>
    </svg>`;
  }

  let ASSETS = [], ALERTS = [], UNREAD = 0, TOTAL_SCANS = 0, VIEW = "dashboard", polling = null, SEQ = false, ADMIN = false, ME = null, EVENTS = [], FOCUS = null, SCAN_KIND = "web", SHOW_TOUR = false;

  // The target icon that flows through the padlock. Web assets show the site's
  // real favicon (fetched server-side); repos and artifacts show a glyph.
  function flowIcon(asset) {
    const glyph = asset?.kind === "repo" ? ic("code", 18) : asset?.kind === "artifact" ? ic("finger", 18) : ic("globe", 18);
    const img = asset?.kind === "web" ? `<img class="fav" src="/api/favicon?u=${encodeURIComponent(asset.target)}" alt="">` : "";
    return `<div class="flow"><span class="glyph">${glyph}</span>${img}</div>`;
  }
  // Which asset the big padlock represents right now.
  function focusAsset() {
    return ASSETS.find((a) => a.id === FOCUS) || ASSETS.find((a) => a.shield === "scanning") || ASSETS[0] || null;
  }

  // ---------- shell ----------
  function shell() {
    const nav = [["dashboard", "home", "Dashboard"], ["assets", "assets", "Assets"], ["scans", "scans", "Scans"], ["reports", "reports", "Reports"], ["settings", "gear", "Settings"]];
    if (ADMIN) nav.push(["admin", "key", "Admin"]);
    root.innerHTML = `<div class="app">
      <aside class="side">
        <div class="logo"><img src="/logo.png" alt=""><div class="wm"><b>LUCENT</b><span>SHIELD</span></div></div>
        <nav class="nav">${nav.map(([v, i, l]) => `<a data-view="${v}" class="${VIEW === v ? "on" : ""}"><span class="ic">${ic(i)}</span>${l}</a>`).join("")}</nav>
        <div class="foot"><img src="/logo.png" alt="">Built for a safer digital world.</div>
      </aside>
      <main class="main">
        <div class="topbar">
          <div class="crumbs">Scan · Detect · <b>Secure</b></div>
          <div class="sp"></div>
          ${watchBtn("watchTop")}
          <button class="iconbtn" id="bell">${ic("bell")}<span class="badge" id="bellBadge" hidden>0</span></button>
          <div class="user"><span class="av">${esc(initials(ME?.name || ME?.email))}</span><b>${esc(ME?.name || "")}</b>${ADMIN ? `<span class="tag secure">Admin</span>` : ""}</div>
        </div>
        <div class="content" id="view"></div>
        <div class="content"><div class="appfoot">
          <span>Created by Bash Lucent</span><span class="sp"></span>
          <a href="/about" target="_blank">About</a><a href="/terms" target="_blank">Terms</a><a href="/privacy" target="_blank">Privacy</a>
          <span>© 2026 Bash Lucent</span>
        </div></div>
      </main>
    </div>`;
    root.querySelector(".nav").onclick = (e) => { const a = e.target.closest("a"); if (a) { VIEW = a.dataset.view; shell(); renderView(); } };
    document.getElementById("bell").onclick = openAlerts;
    document.getElementById("watchTop").onclick = watchGuide;
    setBell(UNREAD);
  }

  function initials(n) { const p = String(n || "?").trim().split(/[\s@.]+/).filter(Boolean); return ((p[0]?.[0] || "?") + (p[1]?.[0] || "")).toUpperCase(); }

  /** The guided video. Opens wherever a "How it works" button is pressed. */
  function watchGuide() { if (window.LucentTour) window.LucentTour.open(); }
  const watchBtn = (id, label = "How it works") => `<button type="button" class="watch-btn" id="${id}"><span class="pl">▶</span>${label}</button>`;

  function setBell(n) { UNREAD = n; const b = document.getElementById("bellBadge"); if (b) { b.hidden = !n; b.textContent = n > 99 ? "99+" : n; } }

  function renderView() {
    const el = document.getElementById("view");
    if (VIEW === "dashboard") el.innerHTML = dashboardView();
    else if (VIEW === "assets") { el.innerHTML = assetsView(); wireAssets(); }
    else if (VIEW === "reports" || VIEW === "scans") el.innerHTML = reportsView();
    else if (VIEW === "settings") { el.innerHTML = settingsView(); wireSettings(); }
    else if (VIEW === "admin" && ADMIN) { el.innerHTML = `<div class="empty">Loading the admin view…</div>`; loadAdmin(); }
    if (VIEW === "dashboard") wireDashboard();
  }

  // ---------- dashboard ----------
  // The dashboard follows the real order of work: 1) choose a scan type and
  // scan, watching the findings stream in, 2) protect the asset, which closes
  // the padlock and keeps watching it. The padlock always shows ONE asset.
  const SCAN_TYPES = [
    { kind: "repo", icon: "code", title: "White box", sub: "Your code: secrets, risky code, vulnerable packages", ph: "https://github.com/you/your-repo", btn: "Scan code" },
    { kind: "web", icon: "mask", title: "Black box", sub: "Your live website, seen from outside", ph: "https://yoursite.com", btn: "Scan website" },
    { kind: "artifact", icon: "finger", title: "Forensics", sub: "Examine a file on this server", ph: "/path/to/evidence", btn: "Examine" },
  ];
  const typesFor = () => SCAN_TYPES.filter((t) => ADMIN || t.kind !== "artifact");
  const openBad = (a) => (a?.counts?.critical || 0) + (a?.counts?.high || 0);
  const openAny = (a) => openBad(a) + (a?.counts?.medium || 0) + (a?.counts?.low || 0);
  const hostOf = (t) => String(t || "").replace(/^https?:\/\//i, "").replace(/\/.*$/, "");

  /** What the padlock shows for one asset. Closed only when it is protected. */
  function lockState(a) {
    if (!a) return "new";
    if (a.shield === "scanning") return "scanning";
    if (!a.lastScanAt) return a.kind === "web" && !a.verified ? "unverified" : "new";
    if (a.shield === "new") return "unreached";
    if (a.monitor) return openBad(a) ? "watching" : "secure";
    if (openBad(a)) return "exposed";
    if (openAny(a)) return "at_risk";
    return "ready";
  }
  const LOCK_WORD = { unreached: "NOT REACHED", new: "", unverified: "NOT VERIFIED", scanning: "SCANNING", exposed: "EXPOSED", at_risk: "OPEN", ready: "NOT PROTECTED", watching: "PROTECTED", secure: "SECURED", securing: "LOCKING" };

  function statsView() {
    const total = ASSETS.length, prot = ASSETS.filter((a) => a.monitor).length, exposed = ASSETS.filter((a) => openBad(a) > 0).length;
    const stat = (cls, icon, label, n, sub, subcls = "") => `<div class="stat"><div class="si ${cls}">${ic(icon, 20)}</div><div><div class="l">${label}</div><div class="n">${n}</div><div class="sub ${subcls}">${sub}</div></div></div>`;
    return `<div class="stats">
      ${stat("blue", "globe", "Assets", total, `${ASSETS.filter((a) => !a.lastScanAt).length} not scanned yet`)}
      ${stat("green", "shield", "Protected", prot, prot ? "Watched around the clock" : "Press Protect after a scan", prot ? "ok" : "")}
      ${stat("red", "alert", "Exposed", exposed, exposed ? "Critical or high issues open" : "No critical or high issues", exposed ? "bad" : "ok")}
      ${stat("violet", "radar", "Scans run", TOTAL_SCANS, "by your account")}
    </div>`;
  }

  function shieldLockSvg() {
    return `<svg class="biglock" viewBox="0 0 160 180" aria-hidden="true">
      <ellipse class="glow" cx="80" cy="98" rx="70" ry="64"/>
      <path class="shield" d="M80 6 L146 30 V84 C146 128 118 160 80 174 C42 160 14 128 14 84 V30 Z"/>
      <g transform="translate(35 40) scale(.75)">
        <path class="shackle" d="M38 58 V42 a22 22 0 0 1 44 0 V58"/>
        <rect class="body" x="26" y="58" width="68" height="62" rx="14"/>
        <circle class="keyhole" cx="60" cy="86" r="7"/><rect class="stem" x="57" y="88" width="6" height="16" rx="3"/>
      </g>
    </svg>`;
  }

  function lockView(a, st) {
    return `<div class="herolock ${st}" id="herolock">
      <div class="halo"></div><div class="rings"></div>
      <div class="orbit">
        <svg class="wires" viewBox="-160 -160 320 320" aria-hidden="true">
          <circle class="track" cx="0" cy="0" r="140"/>
          <line class="wire" x1="0" y1="-92" x2="0" y2="-140"/><line class="wire" x1="80" y1="0" x2="140" y2="0"/>
          <line class="wire" x1="0" y1="92" x2="0" y2="140"/><line class="wire" x1="-80" y1="0" x2="-140" y2="0"/>
        </svg>
        <span class="node nT"><span class="lbl">${ic("code", 18)}</span></span>
        <span class="node nR"><span class="lbl">API</span></span>
        <span class="node nB"><span class="lbl">${ic("db", 18)}</span></span>
        <span class="node nL"><span class="lbl">${ic("server", 18)}</span></span>
      </div>
      ${flowIcon(a)}
      <div class="scanline"></div>
      ${shieldLockSvg()}
      <div class="statusword" id="statusword">${LOCK_WORD[st] || ""}</div>
      ${a ? `<div class="lockname">${esc(a.name)}</div>` : ""}
    </div>`;
  }

  /** The panel under the log: what to do next with the asset on the padlock. */
  function nextStep(a) {
    if (!a) return "";
    const st = lockState(a);
    if (st === "unverified") return `<div class="next">
      <div class="nt"><b>Prove you own ${esc(hostOf(a.target))}</b><span>Lucent Shield scans a website only after its owner proves control of it.</span></div>
      <button class="btn" data-act="verify" data-id="${a.id}">Verify ownership</button></div>`;
    if (!a.lastScanAt) return `<div class="next"><div class="nt"><b>${esc(a.name)} is ready to scan</b></div><button class="btn" data-act="scan" data-id="${a.id}">Scan now</button></div>`;
    if (st === "unreached") return `<div class="next">
      <div class="nt"><b>${esc(a.name)} could not be checked</b><span>${a.kind === "web" ? "The site did not answer. Check the address is right and the site is online, then scan again." : "The repository could not be downloaded. Check the address. Private repositories cannot be read yet."}</span></div>
      <button class="btn" data-act="scan" data-id="${a.id}">Scan again</button></div>`;
    if (!a.monitor) return `<div class="next protect">
      <div class="nt"><b>Protect ${esc(a.name)}</b><span>Lucent Shield keeps checking it every few hours and alerts you the moment something changes, like a new exposed file, a weakened setting or a new vulnerable package.</span></div>
      <div class="na">${openAny(a) ? `<button class="ghost" data-act="report" data-id="${a.id}">See the fixes</button>` : ""}<button class="btn" data-act="protect" data-id="${a.id}">${ic("shield", 16)} Protect</button></div></div>`;
    return `<div class="next on">
      <div class="nt"><b>${openBad(a) ? `Protected, with ${openBad(a)} ${openBad(a) === 1 ? "fix" : "fixes"} still to make` : "Protected and secure"}</b>
      <span>${openBad(a) ? "Lucent Shield is watching it. The padlock turns fully green once the critical and high issues are fixed and a scan confirms it." : "Lucent Shield is watching it and will alert you if anything changes."} Last checked ${timeAgo(a.lastScanAt)}.</span></div>
      <div class="na"><button class="ghost" data-act="report" data-id="${a.id}">Report</button><button class="ghost" data-act="scan" data-id="${a.id}">Scan again</button></div></div>`;
  }

  function heroView() {
    const a = focusAsset();
    const st = lockState(a);
    const type = typesFor().find((t) => t.kind === SCAN_KIND) || typesFor()[1] || typesFor()[0];
    const title = !a ? "Scan, then protect" : st === "secure" ? `${esc(a.name)} is protected` : st === "watching" ? `${esc(a.name)} is being watched` : st === "exposed" ? `${esc(a.name)} is exposed` : st === "unverified" ? `Verify ${esc(hostOf(a.target))}` : `${esc(a.name)}`;
    const step = !a || !a.lastScanAt ? 1 : a.monitor ? 3 : 2;
    return `<div class="hero ${st}" id="hero">
      <div class="heroL">
        <span class="live"><span class="dot"></span>${st === "secure" || st === "watching" ? "Live protection" : "Lucent Shield"}</span>
        <h1 id="heroTitle">${title}</h1>
        <ol class="stepper">
          <li class="${step > 1 ? "done" : "on"}"><span>1</span>Scan</li>
          <li class="${step === 2 ? "on" : step > 2 ? "done" : ""}"><span>2</span>Protect</li>
        </ol>
        <div class="types" role="tablist" aria-label="Scan type">${typesFor().map((t) => `<button role="tab" class="type ${t.kind === type.kind ? "on" : ""}" data-type="${t.kind}" aria-selected="${t.kind === type.kind}">${ic(t.icon, 16)}<span><b>${t.title}</b><small>${t.sub}</small></span></button>`).join("")}</div>
        <div class="scanbar" id="heroScanbar">
          <div class="in">${ic(type.kind === "repo" ? "code" : type.kind === "artifact" ? "finger" : "globe", 16)}<input id="quickUrl" placeholder="${type.ph}" maxlength="2000" aria-label="What to scan"></div>
          <button class="go" id="quickGo">${type.btn}</button>
        </div>
        <div class="err" id="quickErr" role="alert"></div>
        <div class="seq" id="heroSeq" hidden><div class="logstream" id="logstream"></div></div>
        <div id="nextStep">${nextStep(a)}</div>
      </div>
      ${lockView(a, st)}
    </div>`;
  }

  function dashboardView() {
    const preview = ASSETS.slice(0, 5).map((a) => `<div class="row" data-focus="${a.id}" style="cursor:pointer">
      <span class="dotline" style="background:${dotColor(a)}"></span>
      <div class="rt"><div class="t">${esc(a.name)}</div><div class="s">${KIND_LABEL[a.kind]} · ${a.lastScanAt ? `scanned ${timeAgo(a.lastScanAt)}` : a.kind === "web" && !a.verified ? "ownership not verified" : "not scanned"}</div></div>
      ${a.monitor ? `<span class="tag secure">Protected</span>` : a.lastScanAt ? `<span class="tag ${a.shield}">${STATE_LABEL[a.shield]}</span>` : `<span class="tag new">New</span>`}</div>`).join("") || `<div class="empty">Nothing yet. Choose a scan type above and scan something you own.</div>`;
    const activity = buildActivity().slice(0, 7).map((e) => `<div class="row"><span class="dotline" style="background:${e.color}"></span><div class="rt"><div class="t">${esc(e.text)}</div><div class="s">${timeAgo(e.when)}</div></div></div>`).join("") || `<div class="empty">No activity yet.</div>`;
    return statsView() + heroView() + `<div class="cols two">
      <div class="pnl"><div class="ph"><h3>${ic("assets", 16)} Your assets</h3><button class="all" data-view="assets">View all</button></div>${preview}</div>
      <div class="pnl"><div class="ph"><h3>${ic("reports", 16)} Recent activity</h3><button class="all" id="actAll">Alerts</button></div>${activity}</div>
    </div>`;
  }

  function dotColor(a) {
    const st = lockState(a);
    return st === "secure" ? "var(--green)" : st === "exposed" || st === "watching" && openBad(a) ? "var(--red)" : st === "at_risk" ? "var(--amber)" : "var(--muted)";
  }

  /** Only things that really happened, recorded by the server. */
  function buildActivity() {
    const color = { added: "var(--muted)", verified: "var(--cyan)", "protect-on": "var(--green)", "protect-off": "var(--amber)", removed: "var(--muted)" };
    const items = EVENTS.map((e) => ({ text: e.text, when: e.at, color: e.type === "scan" || e.type === "autoscan" ? (e.shield === "exposed" ? "var(--red)" : e.shield === "at_risk" ? "var(--amber)" : "var(--green)") : color[e.type] || "var(--muted)" }));
    for (const al of ALERTS) items.push({ text: al.message.replace(/^[🔓🔒]\s*Lucent Shield:\s*/, ""), when: al.at, color: al.type === "recovered" ? "var(--green)" : "var(--red)" });
    return items.sort((x, y) => new Date(y.when) - new Date(x.when));
  }

  function wireDashboard() {
    const go = document.getElementById("quickGo"), url = document.getElementById("quickUrl");
    const run = () => startScan(SCAN_KIND, url.value.trim());
    if (go) go.onclick = run;
    if (url) url.onkeydown = (e) => { if (e.key === "Enter") run(); };
    document.getElementById("view").onclick = (e) => {
      const t = e.target.closest("[data-type]")?.dataset.type;
      if (t) { SCAN_KIND = t; renderView(); document.getElementById("quickUrl")?.focus(); return; }
      const act = e.target.closest("[data-act]");
      if (act) {
        const a = ASSETS.find((x) => x.id === act.dataset.id); if (!a) return;
        const k = act.dataset.act;
        if (k === "verify") openVerify(a, (fresh) => runScan(fresh));
        else if (k === "scan") runScan(a);
        else if (k === "protect") protect(a);
        else if (k === "report") openReport(a.id);
        return;
      }
      const f = e.target.closest("[data-focus]")?.dataset.focus;
      if (f) { FOCUS = f; renderView(); window.scrollTo({ top: 0, behavior: "smooth" }); return; }
      const view = e.target.closest("[data-view]")?.dataset.view;
      if (view) { VIEW = view; shell(); renderView(); }
      else if (e.target.id === "actAll") openAlerts();
    };
  }

  // ---------- the live scan and protect sequences ----------
  const heroEl = (id) => document.getElementById(id);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  function setLock(state, asset) {
    const l = heroEl("herolock"), h = heroEl("hero");
    if (l) l.className = "herolock " + state;
    if (h) h.className = "hero " + state;
    const s = heroEl("statusword"); if (s) s.textContent = LOCK_WORD[state] || "";
    const live = h?.querySelector(".live"); if (live) live.lastChild.textContent = state === "secure" || state === "watching" ? "Live protection" : "Lucent Shield";
    if (asset) {
      const step = !asset.lastScanAt ? 1 : asset.monitor ? 3 : 2;
      h?.querySelectorAll(".stepper li").forEach((li, i) => { li.className = i + 1 < step ? "done" : i + 1 === step ? "on" : ""; });
    }
  }
  function setTitle(t) { const e = heroEl("heroTitle"); if (e) e.textContent = t; }
  function startLog() {
    const s = heroEl("heroSeq"); if (s) s.hidden = false;
    const ls = heroEl("logstream"); if (ls) ls.innerHTML = "";
    const n = heroEl("nextStep"); if (n) n.innerHTML = "";
  }
  function logLine(cls, html) {
    const ls = heroEl("logstream"); if (!ls) return;
    const mark = cls === "ok" ? "✓" : cls === "bad" ? "✕" : cls === "warn" ? "!" : cls === "run" ? "›" : "·";
    const d = document.createElement("div"); d.className = "logline";
    d.innerHTML = `<span class="${cls || "run"}">${mark}</span> ${html}`;
    ls.appendChild(d); while (ls.children.length > 7) ls.removeChild(ls.firstChild);
  }
  const sevClass = (s) => (s === "critical" || s === "high" ? "bad" : s === "medium" ? "warn" : "");

  function quickErr(msg) { const e = heroEl("quickErr"); if (e) e.textContent = msg || ""; }

  /** Step 1: the scan type and target typed into the hero. */
  async function startScan(kind, raw) {
    quickErr("");
    let target = raw.trim();
    if (!target) return quickErr(kind === "repo" ? "Paste the address of your repository." : kind === "web" ? "Type the address of your website." : "Type the path of the file.");
    if (kind === "web") {
      if (!/^https?:\/\//i.test(target)) target = "https://" + target;
      try { const u = new URL(target); if (!u.hostname.includes(".")) throw 0; target = `${u.protocol}//${u.host}`; } catch { return quickErr("That does not look like a website address, for example https://yoursite.com."); }
    }
    if (kind === "repo" && !ADMIN && !/^https:\/\/[\w.-]+\/[\w.-]+\/[\w.-]+/i.test(target)) return quickErr("Use the repository's web address, for example https://github.com/you/your-repo.");
    const existing = ASSETS.find((a) => a.kind === kind && a.target.replace(/\/$/, "").toLowerCase() === target.replace(/\/$/, "").toLowerCase());
    if (existing) { FOCUS = existing.id; renderView(); return runScan(existing); }
    const auth = await authorizeScan(kind, target);
    if (!auth) return;
    const name = kind === "repo" ? target.replace(/\.git$/, "").split("/").filter(Boolean).slice(-1)[0] : kind === "web" ? hostOf(target) : target.split(/[\\/]/).pop();
    let asset;
    try { asset = (await api("/api/assets", { method: "POST", body: { name, kind, target, authorized: true } })).asset; }
    catch (ex) { return quickErr(ex.message); }
    await refresh();
    FOCUS = asset.id;
    const fresh = ASSETS.find((a) => a.id === asset.id) || asset;
    renderView();
    if (kind === "web" && !fresh.verified) { openVerify(fresh, (v) => runScan(v, auth)); return; }
    runScan(fresh, auth);
  }

  const LOG_STEPS = {
    web: (h) => [["run", `Resolving <b>${esc(h)}</b>`], ["run", "Opening a secure connection"], ["", "Checking HTTPS, the certificate and HSTS"], ["", "Reading the security headers"], ["", "Inspecting cookies"], ["", "Looking for files that should never be public"], ["", "Checking email spoofing protection"]],
    repo: (h) => [["run", `Downloading <b>${esc(h)}</b>`], ["", "Searching for leaked keys and passwords"], ["", "Checking risky code patterns"], ["", "Following request input through the code"], ["", "Checking packages for known vulnerabilities"], ["", "Reviewing Docker, CI and cloud settings"]],
    artifact: (h) => [["run", `Fingerprinting <b>${esc(h)}</b>`], ["", "Looking for secrets inside"], ["", "Checking for signs of tampering"]],
  };

  /** Runs a scan with the live log, then shows what to do next. */
  async function runScan(asset, auth) {
    if (SEQ) return;
    if (asset.kind === "web" && !asset.verified) return openVerify(asset, (v) => runScan(v, auth));
    if (!auth) { auth = await authorizeScan(asset.kind, asset.target); if (!auth) return; }
    if (VIEW !== "dashboard") { VIEW = "dashboard"; shell(); }
    FOCUS = asset.id;
    renderView();
    SEQ = true;
    startLog(); setLock("scanning"); setTitle(`Scanning ${asset.name}…`);
    const scanP = scanApi(asset.id, auth, asset.kind).then((r) => r, (ex) => ({ error: ex.message }));
    for (const [c, t] of LOG_STEPS[asset.kind](asset.name)) { logLine(c, t); await wait(480); }
    logLine("run", "Scoring what was found…");
    const res = await scanP;
    await wait(350);
    const a = res?.asset;
    if (!a) { logLine("bad", esc(res?.error || "The scan could not finish. Check the address and try again.")); setLock(lockState(asset)); SEQ = false; return; }
    TOTAL_SCANS++;
    const findings = (a.findings || []).filter((f) => f.severity !== "info").sort((x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity));
    if (findings.length) {
      logLine("run", `${findings.length} issue${findings.length === 1 ? "" : "s"} found:`);
      for (const f of findings.slice(0, 7)) { await wait(380); logLine(sevClass(f.severity), `<b>${f.severity.toUpperCase()}</b> ${esc(f.title)}`); }
      if (findings.length > 7) { await wait(300); logLine("", `…and ${findings.length - 7} more in the report`); }
    } else {
      const note = (a.findings || []).find((f) => /^(scan|repo)\./.test(f.rule));
      logLine(note ? "warn" : "ok", note ? esc(note.title) : "No issues found");
    }
    await wait(500);
    ASSETS = ASSETS.map((x) => (x.id === a.id ? { ...x, ...a } : x));
    const st = lockState({ ...asset, ...a });
    setLock(st, { ...asset, ...a });
    setTitle(st === "exposed" ? `${a.name} is exposed` : st === "secure" ? `${a.name} is protected` : st === "unreached" ? `${a.name} could not be checked` : a.name);
    if (st !== "unreached") logLine(openBad(a) ? "bad" : openAny(a) ? "warn" : "ok", openBad(a) ? `${openBad(a)} critical or high. Fix these first.` : openAny(a) ? "No critical or high issues." : "Clean.");
    const n = heroEl("nextStep"); if (n) n.innerHTML = nextStep({ ...asset, ...a });
    SEQ = false;
    refreshQuiet();
  }

  /** Step 2: Protect. A standing permission to keep checking, then the padlock closes. */
  async function protect(asset) {
    const ok = await confirmBox({
      title: "Protect " + asset.name,
      body: `<p>Lucent Shield will check <b>${esc(asset.name)}</b> again every few hours, using the same read-only checks, and alert you the moment something changes.</p>
        <label class="chk2"><input type="checkbox" id="cbAuth"><span>I own ${asset.kind === "web" ? "this website" : "this code"} or am authorised to test it, and I permit Lucent Shield to keep checking it until I pause protection.</span></label>`,
      go: "Turn on protection", needCheck: true,
    });
    if (!ok) return;
    SEQ = true;
    startLog(); setLock("securing"); setTitle(`Protecting ${asset.name}…`);
    let a;
    try { a = (await api(`/api/assets/${asset.id}/monitor`, { method: "POST", body: { on: true, authorized: true } })).asset; }
    catch (ex) { logLine("bad", esc(ex.message)); setLock(lockState(asset)); SEQ = false; return; }
    const steps = asset.kind === "web"
      ? ["Saving a baseline of the site's security settings", "Watching certificates, headers and public files", "Arming alerts for any change"]
      : ["Saving a baseline of the code's findings", "Watching for new secrets and vulnerable packages", "Arming alerts for any change"];
    for (const s of steps) { logLine("", s); await wait(520); logLine("ok", s.replace(/^(Saving|Watching|Arming)/, (m) => ({ Saving: "Saved", Watching: "Watching", Arming: "Armed" }[m]))); await wait(260); }
    ASSETS = ASSETS.map((x) => (x.id === a.id ? { ...x, ...a } : x));
    const st = lockState(a);
    setLock(st, a);
    setTitle(st === "secure" ? `${a.name} is protected` : `${a.name} is being watched`);
    logLine(st === "secure" ? "ok" : "warn", st === "secure" ? "Locked. Protection is live." : `Protection is live. ${openBad(a)} critical or high ${openBad(a) === 1 ? "issue is" : "issues are"} still open: fix ${openBad(a) === 1 ? "it" : "them"} to turn the padlock green.`);
    const n = heroEl("nextStep"); if (n) n.innerHTML = nextStep(a);
    SEQ = false;
    refreshQuiet();
  }

  /** A small confirm dialog. Resolves true or false. */
  function confirmBox({ title, body, go, needCheck }) {
    return new Promise((resolve) => {
      const bg = document.createElement("div"); bg.className = "drawer-bg";
      const m = document.createElement("div"); m.className = "authbox"; m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true");
      m.innerHTML = `<div class="ah">${ic("shield", 20)} ${esc(title)}</div>${body}
        <div class="arow"><button class="ghost" id="cbCancel">Cancel</button><button class="btn" id="cbGo" ${needCheck ? "disabled" : ""}>${esc(go)}</button></div>
        <div class="fine">This permission is recorded with a timestamp.</div>`;
      document.body.append(bg, m);
      const done = (v) => { bg.remove(); m.remove(); resolve(v); };
      bg.onclick = () => done(false);
      m.querySelector("#cbCancel").onclick = () => done(false);
      const b = m.querySelector("#cbGo"), c = m.querySelector("#cbAuth");
      if (c) c.onchange = () => { b.disabled = !c.checked; };
      b.onclick = () => { if (!b.disabled) done(true); };
    });
  }

  // Explicit, per-run authorization before ANY test (white box, black box or
  // forensics). Required every time, even after the terms were accepted.
  // Resolves to false (cancelled) or { reference } once the operator affirms.
  function authorizeScan(kind, target) {
    return new Promise((resolve) => {
      const forensic = kind === "artifact";
      const label = kind === "repo" ? "white box (code) scan" : kind === "web" ? "black box (website) scan" : "forensic examination";
      const noun = kind === "repo" ? "repository" : kind === "web" ? "website" : "file or artifact";
      const bg = document.createElement("div"); bg.className = "drawer-bg";
      const m = document.createElement("div"); m.className = "authbox"; m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true");
      m.innerHTML = `
        <div class="ah ${forensic ? "danger" : ""}">${ic("shield", 20)} ${forensic ? "Legal authorization required" : "Authorization required"}</div>
        <p>You are about to run a <b>${label}</b> of:</p>
        <div class="tgt">${esc(target)}</div>
        <p class="warn">${forensic
          ? "Forensic examination can reveal personal and sensitive data. You may only do it with lawful authority: ownership, written permission, or a warrant or court order. Doing it without authority is a serious offence, and the responsibility is entirely yours."
          : `Only scan systems you own or have explicit permission to test. Scanning a ${noun} you are not authorised to test may be illegal, and the responsibility is yours.`}</p>
        ${forensic ? `
        <label class="al">Authorization reference</label>
        <input class="aref" id="authRef" maxlength="200" placeholder="Warrant / court order / written-permission reference">
        <label class="chk2"><input type="checkbox" id="authLegal"><span>I attest that I hold lawful authority (ownership, written permission, or a warrant or court order) to examine this, and I can produce it on request.</span></label>` : ""}
        <label class="chk2"><input type="checkbox" id="authChk"><span>I own this ${noun} or have explicit authorisation to test it, and I give Lucent Shield permission to scan it.</span></label>
        <div class="arow"><button class="ghost" id="authCancel">Cancel</button><button class="btn" id="authGo" disabled>Authorise &amp; scan</button></div>
        <div class="fine">This authorisation${forensic ? " and reference are" : " is"} recorded with a timestamp.</div>`;
      document.body.append(bg, m);
      const done = (v) => { bg.remove(); m.remove(); resolve(v); };
      bg.onclick = () => done(false);
      m.querySelector("#authCancel").onclick = () => done(false);
      const chk = m.querySelector("#authChk"), go = m.querySelector("#authGo");
      const legal = m.querySelector("#authLegal"), ref = m.querySelector("#authRef");
      const sync = () => { go.disabled = !(chk.checked && (!forensic || (legal.checked && ref.value.trim()))); };
      chk.onchange = sync; if (forensic) { legal.onchange = sync; ref.oninput = sync; }
      go.onclick = () => { if (!go.disabled) done({ reference: forensic ? ref.value.trim() : "" }); };
    });
  }

  // Scan an asset through the API with the per-run authorization payload.
  function scanApi(id, auth, kind) {
    return api(`/api/assets/${id}/scan`, { method: "POST", body: { authorized: true, legal: kind === "artifact", reference: auth?.reference || "" } });
  }

  // Domain-ownership verification. The owner picks ONE method, follows its
  // steps, then presses Verify.
  function openVerify(asset, onVerified) {
    const host = hostOf(asset.target);
    const tok = asset.verifyToken;
    const proto = /^http:\/\//i.test(asset.target) ? "http" : "https";
    const fileUrl = `${proto}://${host}/.well-known/lucent-verify.txt`;
    const copyBtn = (v, label = "Copy") => `<button type="button" class="copy" data-copy="${esc(v)}">${label}</button>`;
    const d = drawer(`
      <h2>Verify you own ${esc(host)}</h2>
      <div class="sub">Lucent Shield scans a website only after you prove you control it. Pick one way, follow the steps, then press Verify.</div>
      <div class="vpick" role="radiogroup" aria-label="How to verify">
        <button type="button" role="radio" class="vopt on" data-m="file" aria-checked="true"><b>Upload a file</b><span>Best if you can change your site's files</span></button>
        <button type="button" role="radio" class="vopt" data-m="dns" aria-checked="false"><b>Add a DNS record</b><span>Best if you manage your domain's DNS</span></button>
      </div>
      <div class="vpane" data-pane="file">
        <ol class="vsteps">
          <li><div>Download your verification file. It holds your token and nothing else.</div><a class="btn small" href="data:text/plain;charset=utf-8,${encodeURIComponent(tok)}" download="lucent-verify.txt">Download lucent-verify.txt</a></li>
          <li><div>Put it on your site inside a folder called <code>.well-known</code>, so it opens at this address:</div><div class="tgt">${esc(fileUrl)} ${copyBtn(fileUrl)}</div>
            <div class="hint2">On Vercel, Next.js or Netlify: put it in <code>public/.well-known/lucent-verify.txt</code>, then push and wait for the deploy. On cPanel or plain hosting: upload it into <code>public_html/.well-known/</code>.</div></li>
          <li><div>Open the address. When it shows your token instead of an error page, press Verify.</div><a class="ghost small" href="${esc(fileUrl)}" target="_blank" rel="noopener noreferrer">Open the address</a></li>
        </ol>
      </div>
      <div class="vpane" data-pane="dns" hidden>
        <ol class="vsteps">
          <li><div>Open the DNS settings where your domain is managed (Vercel → Domains, Cloudflare → DNS, or your registrar).</div></li>
          <li><div>Add a record with these values:</div>
            <table class="dns"><tr><th>Type</th><td><code>TXT</code></td></tr><tr><th>Name</th><td><code>@</code> <span class="hint2">(or ${esc(host)})</span></td></tr><tr><th>Value</th><td><code>lucent-verify=${esc(tok)}</code> ${copyBtn(`lucent-verify=${tok}`)}</td></tr></table></li>
          <li><div>Save it, wait a few minutes, then press Verify. DNS changes can take up to an hour.</div></li>
        </ol>
      </div>
      <div class="arow"><button class="btn" id="vGo">Verify ownership</button></div>
      <div class="vstatus" id="vStatus" role="status"></div>`);
    d.querySelectorAll(".vopt").forEach((b) => b.onclick = () => {
      d.querySelectorAll(".vopt").forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-checked", String(x === b)); });
      d.querySelectorAll(".vpane").forEach((p) => { p.hidden = p.dataset.pane !== b.dataset.m; });
    });
    d.querySelectorAll("[data-copy]").forEach((b) => b.onclick = async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1500); } catch { b.textContent = "Select and copy"; }
    });
    const st = d.querySelector("#vStatus"), go = d.querySelector("#vGo");
    go.onclick = async () => {
      st.textContent = "Checking…"; st.className = "vstatus"; go.disabled = true;
      try {
        const r = await api(`/api/assets/${asset.id}/verify`, { method: "POST" });
        if (r.verified) {
          st.textContent = "Verified. You own this site."; st.className = "vstatus ok";
          await refresh();
          setTimeout(() => { d.close(); const fresh = ASSETS.find((a) => a.id === asset.id) || { ...asset, verified: true }; if (onVerified) onVerified(fresh); else renderView(); }, 900);
          return;
        }
        st.textContent = d.querySelector('.vopt[data-m="dns"]').classList.contains("on")
          ? "The record was not found yet. DNS can take a while; try again in a few minutes."
          : `The file was not found at ${fileUrl}, or it does not contain your token. Open that address to check it shows the token, then try again.`;
        st.className = "vstatus bad";
      } catch (ex) { st.textContent = ex.message; st.className = "vstatus bad"; }
      go.disabled = false;
    };
  }

  // ---------- assets view ----------
  function assetsView() {
    return `<form class="add" id="addForm">
        <div class="field"><label>Name</label><input name="name" placeholder="My website" required maxlength="100"></div>
        <div class="field"><label>Kind</label><select name="kind">
          <option value="repo">Code repo (white box)</option><option value="web">Website (black box)</option>${ADMIN ? `<option value="artifact">Artifact (forensics)</option>` : ""}
        </select></div>
        <div class="field"><label>Target</label><input name="target" placeholder="${ADMIN ? "https://github.com/you/repo  ·  /path/on/server  ·  https://yoursite.com" : "https://github.com/you/repo  ·  https://yoursite.com"}" required maxlength="2000"></div>
        <button class="btn" type="submit">Add & scan</button>
        <div class="err" id="addErr"></div>
      </form>
      <div class="grid" id="grid">${ASSETS.length ? ASSETS.map(cardHtml).join("") : `<div class="empty">No assets yet. Add one above.</div>`}</div>`;
  }

  function cardHtml(a) {
    const pills = [["c", a.counts.critical, "critical"], ["h", a.counts.high, "high"], ["m", a.counts.medium, "medium"], ["l", a.counts.low, "low"]]
      .filter(([, n]) => n).map(([cl, n, l]) => `<span class="pill ${cl}">${n} ${l}</span>`).join("");
    const unverified = a.kind === "web" && !a.verified;
    return `<div class="card s-${a.shield}" data-id="${a.id}">
      <span class="kind">${KIND_LABEL[a.kind] || a.kind}</span>
      ${a.kind !== "artifact" && a.lastScanAt ? `<button class="mon ${a.monitor ? "on" : ""}" data-act="mon" title="${a.monitor ? "Protected. Click to pause" : "Not protected. Click to protect"}">${a.monitor ? "● protected" : "○ not protected"}</button>` : ""}
      <button class="del" data-act="del" title="Remove">✕</button>
      ${lockSvg("padlock")}
      <div class="name">${esc(a.name)}</div>
      <div class="target">${esc(a.target)}</div>
      ${unverified ? `<div class="unver">⚠ Ownership not verified</div>` : a.kind === "web" ? `<div class="ver">✓ Ownership verified</div>` : ""}
      <div class="state">${STATE_LABEL[a.shield]}</div>
      ${pills ? `<div class="counts">${pills}</div>` : ""}
      ${a.lastScanAt ? `<div class="scanned">scanned ${timeAgo(a.lastScanAt)}</div>` : ""}
      <div class="actions">${unverified ? `<button data-act="verify">Verify ownership</button>` : `<button data-act="scan">Scan now</button>`}${a.lastScanAt ? `<button data-act="view">Report</button>` : ""}</div>
    </div>`;
  }

  function wireAssets() {
    const form = document.getElementById("addForm"), kindSel = form.kind;
    form.onsubmit = async (e) => {
      e.preventDefault(); const err = document.getElementById("addErr"); err.textContent = "";
      const name = form.name.value.trim(), kind = kindSel.value, target = form.target.value.trim();
      if (!name || !target) { err.textContent = "Give it a name and a target."; return; }
      const auth = await authorizeScan(kind, target);
      if (!auth) return;
      try {
        const { asset } = await api("/api/assets", { method: "POST", body: { name, kind, target, authorized: true } });
        form.reset(); await refresh(); renderView(); scanAsset(asset.id, { preauth: true, auth });
      } catch (ex) { err.textContent = ex.message; }
    };
    document.getElementById("grid").onclick = (e) => {
      const card = e.target.closest(".card"); if (!card) return;
      const id = card.dataset.id, act = e.target.dataset.act;
      if (act === "scan") scanAsset(id);
      else if (act === "verify") { const a = ASSETS.find((x) => x.id === id); if (a) openVerify(a, () => renderView()); }
      else if (act === "view") openReport(id); else if (act === "del") removeAsset(id); else if (act === "mon") toggleMonitor(id);
    };
  }

  function cardEl(id) { return document.querySelector(`.card[data-id="${id}"]`); }
  function setCard(id) { const a = ASSETS.find((x) => x.id === id), el = cardEl(id); if (a && el) el.outerHTML = cardHtml(a); }

  async function scanAsset(id, opts = {}) {
    const a0 = ASSETS.find((x) => x.id === id); if (!a0) return;
    // A website must prove ownership before it can be scanned.
    if (a0.kind === "web" && !a0.verified) { openVerify(a0, () => scanAsset(id, opts)); return; }
    let auth = opts.auth;
    if (!opts.preauth) { auth = await authorizeScan(a0.kind, a0.target); if (!auth) return; }
    const el = cardEl(id);
    if (el) { el.className = "card s-scanning scan-sweep"; const s = el.querySelector(".state"); if (s) s.textContent = "Scanning…"; }
    if (VIEW === "dashboard") { const hs = document.querySelector(".herolock"); if (hs) hs.className = "herolock scanning"; }
    try {
      const { asset } = await scanApi(id, auth, a0.kind);
      ASSETS = ASSETS.map((a) => (a.id === id ? { ...a, ...asset } : a));
      await refreshCounts();
      if (VIEW === "assets") setCard(id); else renderView();
    } catch { if (el) el.querySelector(".state").textContent = "Scan failed"; }
  }

  async function toggleMonitor(id) {
    const a = ASSETS.find((x) => x.id === id); if (!a) return;
    if (!a.monitor) { VIEW = "dashboard"; FOCUS = id; shell(); renderView(); protect(a); return; }
    const ok = await confirmBox({ title: "Pause protection", body: `<p>Lucent Shield will stop checking <b>${esc(a.name)}</b> until you protect it again.</p>`, go: "Pause protection" });
    if (!ok) return;
    try { const { asset } = await api(`/api/assets/${id}/monitor`, { method: "POST", body: { on: false } }); ASSETS = ASSETS.map((x) => (x.id === id ? { ...x, ...asset } : x)); setCard(id); refreshQuiet(); } catch {}
  }

  async function removeAsset(id) {
    const a = ASSETS.find((x) => x.id === id);
    const ok = await confirmBox({ title: "Remove " + (a?.name || "asset"), body: "<p>Its scan results and protection will be removed. The authorization records are kept.</p>", go: "Remove" });
    if (!ok) return;
    await api(`/api/assets/${id}`, { method: "DELETE" }); if (FOCUS === id) FOCUS = null; await refresh(); renderView();
  }

  async function openReport(id) {
    const { asset } = await api(`/api/assets/${id}`);
    const f = asset.findings || [];
    const body = f.length ? f.map((x) => `<div class="finding"><div class="fh"><span class="sev ${x.severity}">${x.severity}</span><span class="ft">${esc(x.title)}</span></div>${x.location ? `<div class="loc">${esc(x.location)}${x.line ? ":" + x.line : ""}</div>` : ""}${x.evidence ? `<pre>${esc(x.evidence)}</pre>` : ""}<div class="detail">${esc(x.detail)}</div><div class="fix"><b>How to fix:</b> ${esc(x.remediation)}</div></div>`).join("")
      : `<div class="clean-note">No issues in the last scan. The padlock is green. Keep scanning after changes.</div>`;
    const base = `/api/assets/${asset.id}/report`;
    const dl = asset.lastScanAt ? `<div class="repbar"><a class="btn" href="${base}?view=1" target="_blank" rel="noopener">${ic("reports", 16)} Full assessment report (PDF)</a>
      <a class="ghost" href="${base}?format=html">HTML</a><a class="ghost" href="${base}?format=md">Markdown</a><a class="ghost" href="${base}?format=json">JSON</a></div>` : "";
    drawer(`<h2>${esc(asset.name)}</h2><div class="sub">${esc(asset.target)} · scanned ${asset.lastScanAt ? new Date(asset.lastScanAt).toLocaleString() : "never"}</div>${dl}${body}`);
  }

  async function openAlerts() {
    const { alerts } = await api("/api/alerts"); await api("/api/alerts/read-all", { method: "POST" }).catch(() => {});
    ALERTS = alerts; setBell(0);
    const body = alerts.length ? alerts.map((a) => `<div class="alert ${a.type}"><div>${esc(a.message)}</div><div class="awhen">${new Date(a.at).toLocaleString()}</div></div>`).join("") : `<div class="clean-note">No alerts yet. When a watched asset changes, it shows here.</div>`;
    drawer(`<h2>Alerts</h2><div class="sub">Changes to your watched assets, newest first.</div>${body}`);
  }

  function drawer(html) {
    const bg = document.createElement("div"); bg.className = "drawer-bg";
    const d = document.createElement("div"); d.className = "drawer";
    d.innerHTML = `<button class="x">✕</button>${html}`;
    document.body.append(bg, d);
    const close = () => { bg.remove(); d.remove(); };
    bg.onclick = close; d.querySelector(".x").onclick = close;
    d.close = close;
    return d;
  }

  // ---------- reports / settings ----------
  function reportsView() {
    const act = buildActivity();
    return `<div class="pnl" style="max-width:720px">
      <div class="ph"><h3>${ic("reports", 16)} Activity & alerts</h3><button class="all" id="clearBell">Mark read</button></div>
      ${act.length ? act.map((e) => `<div class="row"><span class="dotline" style="background:${e.color}"></span><div class="rt"><div class="t">${esc(e.text)}</div><div class="s">${new Date(e.when).toLocaleString()}</div></div></div>`).join("") : `<div class="empty">Nothing yet. Scans and alerts will appear here.</div>`}
    </div>`;
  }

  function settingsView() {
    const watching = ASSETS.filter((a) => a.monitor).length;
    const two = ME?.twoStep;
    return `<div class="set">
      <div class="kv"><span class="k">Account</span><span>${esc(ME?.name || "")} · ${esc(ME?.email || "")}</span></div>
      <div class="kv"><span class="k">Monitored assets</span><b>${watching} of ${ASSETS.length}</b></div>
      ${ADMIN ? `<div class="kv"><span class="k">Auto re-scan</span><span>On the server schedule (<code>LUCENT_SCAN_INTERVAL_MIN</code>)</span></div>
      <div class="kv"><span class="k">Alerts webhook</span><span>Set <code>LUCENT_ALERT_WEBHOOK</code> to also send to Slack/Discord</span></div>` : ""}
      <div class="kv"><span class="k">Guided video</span>${watchBtn("watchSet", "Watch how it works")}</div>
      <div class="kv"><span class="k">Signed in</span><button class="btn" id="logout" style="padding:7px 14px">Log out</button></div>
    </div>
    <div class="set twostep" id="twoStep">
      <div class="ts-head"><div><h3>Two-step login</h3>
        <p>${two ? `On. Logging in needs your password and a code from your authenticator app. ${ME.recoveryLeft} recovery ${ME.recoveryLeft === 1 ? "code" : "codes"} left.` : "Protect your account with a code from an authenticator app (Google Authenticator, Microsoft Authenticator, Authy) as well as your password."}</p></div>
        <span class="tag ${two ? "secure" : "at_risk"}">${two ? "On" : "Off"}</span></div>
      <div id="tsBody">${two
        ? `<button class="btn ghost-btn" id="tsOffStart" type="button">Turn off</button>`
        : `<button class="btn" id="tsStart" type="button">Turn on two-step login</button>`}</div>
    </div>`;
  }

  function qrSvg(text) {
    const m = globalThis.lucentQR.matrix(text), n = m.length + 8;
    let d = "";
    m.forEach((row, r) => row.forEach((v, c) => { if (v) d += `M${c + 4} ${r + 4}h1v1h-1z`; }));
    return `<svg class="qr" viewBox="0 0 ${n} ${n}" role="img" aria-label="QR code for your authenticator app"><rect width="${n}" height="${n}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
  }

  function wireSettings() {
    const b = document.getElementById("logout");
    if (b) b.onclick = async () => { if (polling) clearInterval(polling); await api("/api/logout", { method: "POST" }); boot(); };
    const w = document.getElementById("watchSet"); if (w) w.onclick = watchGuide;
    const body = document.getElementById("tsBody");
    const err = () => `<div class="err" id="tsErr" role="alert"></div>`;
    const fail = (ex) => { const e = document.getElementById("tsErr"); if (e) e.textContent = ex.message; };
    const done = (u) => { ME = u; renderView(); };

    const start = document.getElementById("tsStart");
    if (start) start.onclick = () => {
      body.innerHTML = `<form id="tsPw" class="tsform"><label class="lf">Confirm your password<input type="password" name="password" autocomplete="current-password" required></label>
        <button class="btn" type="submit">Continue</button>${err()}</form>`;
      const f = document.getElementById("tsPw"); f.password.focus();
      f.onsubmit = async (e) => {
        e.preventDefault();
        try {
          const r = await api("/api/account/2fa/start", { method: "POST", body: { password: f.password.value } });
          body.innerHTML = `<div class="tssetup">
            <div class="qrbox">${qrSvg(r.uri)}</div>
            <div><ol class="steps"><li>Open your authenticator app and add an account.</li><li>Scan this QR code. If you can't scan, type this key instead:<div class="key"><code>${esc(r.secret.replace(/(.{4})/g, "$1 ").trim())}</code></div></li><li>Enter the 6-digit code the app shows.</li></ol>
            <form id="tsCode" class="tsform"><label class="lf">Code from the app<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required></label>
            <button class="btn" type="submit">Turn on</button>${err()}</form></div></div>`;
          const c = document.getElementById("tsCode"); c.code.focus();
          c.onsubmit = async (e2) => {
            e2.preventDefault();
            try {
              const x = await api("/api/account/2fa/enable", { method: "POST", body: { code: c.code.value } });
              ME = x.user;
              const head = document.querySelector("#twoStep .ts-head");
              if (head) { head.querySelector(".tag").className = "tag secure"; head.querySelector(".tag").textContent = "On"; head.querySelector("p").textContent = "On. Logging in needs your password and a code from your authenticator app."; }
              body.innerHTML = `<div class="recovery"><p><b>Two-step login is on.</b> Save these recovery codes somewhere safe, like a password manager or on paper. Each one works once, if you lose your phone. They will not be shown again.</p>
                <div class="codes">${x.recoveryCodes.map((k) => `<code>${esc(k)}</code>`).join("")}</div>
                <button class="btn" id="tsSaved" type="button">I have saved them</button></div>`;
              document.getElementById("tsSaved").onclick = () => done(ME);
            } catch (ex) { fail(ex); }
          };
        } catch (ex) { fail(ex); }
      };
    };

    const off = document.getElementById("tsOffStart");
    if (off) off.onclick = () => {
      body.innerHTML = `<form id="tsOff" class="tsform"><p class="warn">Turning this off makes your account easier to break into.</p>
        <label class="lf">Your password<input type="password" name="password" autocomplete="current-password" required></label>
        <label class="lf">Code from your authenticator app<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required></label>
        <button class="btn danger-btn" type="submit">Turn off two-step login</button>${err()}</form>`;
      const f = document.getElementById("tsOff"); f.password.focus();
      f.onsubmit = async (e) => {
        e.preventDefault();
        try { const x = await api("/api/account/2fa/disable", { method: "POST", body: { password: f.password.value, code: f.code.value } }); done(x.user); }
        catch (ex) { fail(ex); }
      };
    };
  }

  // ---------- admin ----------
  function dur(sec) { const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`; }
  const yes = (on, good = true) => `<span class="tag ${on === good ? "secure" : "exposed"}">${on ? "On" : "Off"}</span>`;

  function EVENT_LABEL(l) {
    const t = { signup: ["Account created", "Sign-up refused"], login: ["Password accepted", "Refused"], code: ["Logged in with code", "Wrong code"], recovery: ["Used a recovery code", "Wrong recovery code"], "2fa-on": ["Two-step turned on", ""], "2fa-off": ["Two-step turned off", ""] }[l.event] || ["Logged in", "Refused"];
    return l.ok ? t[0] : t[1];
  }

  async function loadAdmin() {
    const el = document.getElementById("view");
    let d;
    try { d = await api("/api/admin/overview"); }
    catch (ex) { if (VIEW === "admin") el.innerHTML = `<div class="empty">${esc(ex.message)}</div>`; return; }
    if (VIEW !== "admin") return;
    const t = d.totals, sys = d.system, st = sys.settings;
    const stat = (cls, icon, label, n, sub, subcls = "") => `<div class="stat"><div class="si ${cls}">${ic(icon, 20)}</div><div><div class="l">${label}</div><div class="n">${n}</div><div class="sub ${subcls}">${sub}</div></div></div>`;
    const open = t.severity.critical + t.severity.high;
    const warnings = [];
    if (!ME?.twoStep) warnings.push("Your admin account has no two-step login. Turn it on in Settings: it is the strongest protection against a stolen password.");
    if (!st.signupsOpen) warnings.push("New sign-ups are closed (LUCENT_SIGNUPS=closed). Only existing accounts can log in.");
    if (!st.httpsCookies) warnings.push("The login cookie is not marked Secure. Set TRUST_PROXY=1 when serving over HTTPS.");
    if (st.internalTargetsAllowed) warnings.push("Internal network targets are allowed (LUCENT_ALLOW_INTERNAL=1). Turn this off in production.");
    if (t.failedLogins24h >= 5) warnings.push(`${t.failedLogins24h} failed sign-ins in the last 24 hours. Someone may be guessing the password.`);

    el.innerHTML = `
      <div class="stats">
        ${stat("blue", "assets", "Accounts", t.users, `${t.assets} ${t.assets === 1 ? "asset" : "assets"}: ${t.byKind.repo} code, ${t.byKind.web} sites, ${t.byKind.artifact} forensic`)}
        ${stat("red", "alert", "Critical and high", open, open ? "Open across all assets" : "None open", open ? "bad" : "ok")}
        ${stat("violet", "radar", "Scans run", t.scans, `${t.monitored} ${t.monitored === 1 ? "asset" : "assets"} monitored`)}
        ${stat(t.failedLogins24h ? "red" : "green", "key", "Failed sign-ins", t.failedLogins24h, "in the last 24 hours", t.failedLogins24h ? "bad" : "ok")}
      </div>
      ${warnings.length ? `<div class="pnl adm-warn">${warnings.map((w) => `<div class="row"><span class="dotline" style="background:var(--amber)"></span><div class="rt"><div class="t">${esc(w)}</div></div></div>`).join("")}</div>` : ""}
      <div class="adm-cols">
        <div class="pnl">
          <div class="ph"><h3>${ic("shield", 16)} Authorization audit</h3><a class="all" href="/api/admin/audit.json" download>Download</a></div>
          <p class="adm-note">Every scan is recorded here with who confirmed it, from where, and when. Forensic scans carry their legal reference.</p>
          ${d.authorizations.length ? `<div class="adm-table"><table><thead><tr><th>When</th><th>Asset</th><th>By</th><th>Type</th><th>From</th><th>Reference</th></tr></thead><tbody>
            ${d.authorizations.slice(0, 60).map((a) => `<tr><td>${new Date(a.at).toLocaleString()}</td><td title="${esc(a.target)}">${esc(a.name)}</td><td>${esc(a.email || "")}</td><td>${esc(KIND_LABEL[a.kind] || a.kind)}</td><td class="mono">${esc(a.ip)}</td><td>${esc(a.reference || "")}</td></tr>`).join("")}
          </tbody></table></div>` : `<div class="empty">No scans authorized yet.</div>`}
        </div>
        <div class="pnl">
          <div class="ph"><h3>${ic("key", 16)} Sign-ins</h3></div>
          ${d.logins.length ? `<div class="adm-table"><table><thead><tr><th>When</th><th>Email</th><th>From</th><th>Result</th></tr></thead><tbody>
            ${d.logins.slice(0, 40).map((l) => `<tr><td>${new Date(l.at).toLocaleString()}</td><td>${esc(l.email || "")}</td><td class="mono">${esc(l.ip)}</td><td><span class="tag ${l.ok ? "secure" : "exposed"}">${EVENT_LABEL(l)}</span></td></tr>`).join("")}
          </tbody></table></div>` : `<div class="empty">No sign-ins recorded yet.</div>`}
        </div>
      </div>
      <div class="pnl adm-block">
        <div class="ph"><h3>${ic("key", 16)} Accounts</h3></div>
        ${d.users.length ? `<div class="adm-table"><table><thead><tr><th>Name</th><th>Email</th><th>Created</th><th>Last login</th><th>Two-step</th><th>Assets</th><th>Scans</th></tr></thead><tbody>
          ${d.users.map((u) => `<tr><td><b>${esc(u.name)}</b>${u.admin ? ` <span class="tag secure">Admin</span>` : ""}</td><td>${esc(u.email)}</td><td>${new Date(u.createdAt).toLocaleDateString()}</td><td>${u.lastLoginAt ? timeAgo(u.lastLoginAt) : "never"}</td><td>${u.twoStep ? "On" : "Off"}</td><td>${u.assets}</td><td>${u.scans || 0}</td></tr>`).join("")}
        </tbody></table></div>` : `<div class="empty">No accounts yet.</div>`}
      </div>
      <div class="pnl adm-block">
        <div class="ph"><h3>${ic("assets", 16)} All assets</h3></div>
        ${d.assets.length ? `<div class="adm-table"><table><thead><tr><th>Asset</th><th>Owner</th><th>Type</th><th>State</th><th>Open issues</th><th>Ownership</th><th>Monitor</th><th>Last scan</th></tr></thead><tbody>
          ${d.assets.map((a) => `<tr><td><b>${esc(a.name)}</b><div class="mono sub">${esc(a.target)}</div></td><td>${esc(a.owner || "")}</td><td>${esc(KIND_LABEL[a.kind])}</td><td><span class="tag ${esc(a.shield)}">${esc(STATE_LABEL[a.shield])}</span></td>
            <td>${SEVERITY_ORDER.slice(0, 4).filter((s) => a.counts?.[s]).map((s) => `<span class="sev ${s}">${a.counts[s]} ${s}</span>`).join(" ") || "None"}</td>
            <td>${a.kind === "web" ? (a.verified ? `<span class="tag secure">Verified</span>` : `<span class="tag at_risk">Not verified</span>`) : "Not needed"}</td>
            <td>${a.monitor ? "On" : "Off"}</td><td>${timeAgo(a.lastScanAt)}</td></tr>`).join("")}
        </tbody></table></div>` : `<div class="empty">No assets yet.</div>`}
      </div>
      <div class="adm-cols">
        <div class="set">
          <div class="kv"><span class="k">Version</span><b>${esc(sys.version)}</b></div>
          <div class="kv"><span class="k">Running for</span><span>${dur(sys.uptimeSec)}</span></div>
          <div class="kv"><span class="k">Memory in use</span><span>${sys.memoryMb} MB</span></div>
          <div class="kv"><span class="k">Signed-in sessions</span><span>${sys.activeSessions}</span></div>
          <div class="kv"><span class="k">Node.js</span><span>${esc(sys.node)}</span></div>
        </div>
        <div class="set">
          <div class="kv"><span class="k">New sign-ups</span>${yes(st.signupsOpen)}</div>
          <div class="kv"><span class="k">Secure cookies (HTTPS)</span>${yes(st.httpsCookies)}</div>
          <div class="kv"><span class="k">Private GitHub access</span>${yes(st.githubToken)}</div>
          <div class="kv"><span class="k">Slack or Discord alerts</span>${yes(st.alertWebhook)}</div>
          <div class="kv"><span class="k">Internal targets allowed</span>${yes(st.internalTargetsAllowed, false)}</div>
        </div>
      </div>`;
  }

  // ---------- data ----------
  async function refresh() {
    const d = await api("/api/assets"); ASSETS = d.assets; TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0);
    try { ALERTS = (await api("/api/alerts")).alerts; } catch {}
    try { EVENTS = (await api("/api/activity")).events; } catch {}
  }
  /** Refreshes data and the panels around the hero without restarting its animation. */
  async function refreshQuiet() {
    try { await refresh(); } catch { return; }
    if (VIEW !== "dashboard") return;
    // Swap only the numbers and the lists, so the hero keeps its log on screen.
    const tmp = document.createElement("div"); tmp.innerHTML = dashboardView();
    for (const sel of [".stats", ".cols"]) { const now = document.querySelector(`#view ${sel}`), next = tmp.querySelector(sel); if (now && next) now.replaceWith(next); }
  }
  async function refreshCounts() { try { const d = await api("/api/assets"); TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0); } catch {} }

  async function poll() {
    if (SEQ || document.querySelector(".drawer")) return;
    let d; try { d = await api("/api/assets"); } catch { return; }
    const changed = JSON.stringify(d.assets.map((a) => [a.id, a.shield, a.counts, a.monitor, a.verified, a.lastScanAt])) !== JSON.stringify(ASSETS.map((a) => [a.id, a.shield, a.counts, a.monitor, a.verified, a.lastScanAt]));
    ASSETS = d.assets; TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0);
    if (changed) { try { ALERTS = (await api("/api/alerts")).alerts; EVENTS = (await api("/api/activity")).events; } catch {} renderView(); }
  }

  // ---------- login ----------
  function loginView(signupsOpen = true, mode = "login") {
    const signup = mode === "signup";
    root.innerHTML = `<div class="login"><div class="box">
      <div class="shieldwrap"><div class="glow"></div><div class="ring"></div><img src="/logo.png" alt="Lucent Shield"></div>
      <div class="pill"><span class="d"></span>Protected access</div>
      <h1>${signup ? "Create your account" : "Log in to Lucent Shield"}</h1>
      <p>${signup ? "Scan the code and websites you own, and see exactly how to fix what is exposed." : "Welcome back. Log in to see your assets."}</p>
      <form id="authForm" novalidate>
        ${signup ? `<label class="lf">Name<input name="name" autocomplete="name" maxlength="80" required></label>` : ""}
        <label class="lf">Email<input type="email" name="email" autocomplete="email" maxlength="254" required></label>
        <label class="lf">Password<input type="password" name="password" autocomplete="${signup ? "new-password" : "current-password"}" minlength="${signup ? 10 : 1}" maxlength="200" required></label>
        ${signup ? `<div class="hint">At least 10 characters.</div><label class="agree"><input type="checkbox" name="agree" required><span>I agree to the <a href="/terms" target="_blank">Terms</a> and will only scan what I own or am authorised to test.</span></label>` : ""}
        <button class="btn" type="submit">${signup ? "Create account" : "Log in"}</button><div class="err" id="loginErr" role="alert"></div>
      </form>
      ${signup ? `<div class="switch">Already have an account? <button type="button" id="authSwitch">Log in</button></div>`
        : signupsOpen ? `<div class="switch">New to Lucent Shield? <button type="button" id="authSwitch">Create an account</button></div>` : ""}
      <div class="watchrow">${watchBtn("watchLogin", "Watch how Lucent Shield works")}</div>
      <div class="foot"><a href="/about">About</a><a href="/terms">Terms</a><a href="/privacy">Privacy</a></div>
      <div class="cap">Created by Bash Lucent · © 2026</div>
    </div></div>`;
    document.getElementById("watchLogin").onclick = watchGuide;
    const f = document.getElementById("authForm");
    (f.name || f.email).focus();
    const sw = document.getElementById("authSwitch");
    if (sw) sw.onclick = () => loginView(signupsOpen, signup ? "login" : "signup");
    f.onsubmit = async (e) => {
      e.preventDefault();
      const err = document.getElementById("loginErr"); err.textContent = "";
      const body = { email: f.email.value.trim(), password: f.password.value };
      if (signup) {
        body.name = f.name.value.trim();
        if (!body.name) return void (err.textContent = "Enter your name.");
        if (body.password.length < 10) return void (err.textContent = "Use a password of at least 10 characters.");
        if (!f.agree.checked) return void (err.textContent = "Please agree to the Terms to continue.");
      }
      if (!body.email || !body.password) return void (err.textContent = "Enter your email and password.");
      const btn = f.querySelector("button[type=submit]"); btn.disabled = true;
      try {
        const r = await api(signup ? "/api/signup" : "/api/login", { method: "POST", body });
        if (signup) SHOW_TOUR = true; // a new account gets the guided video once
        if (r.needCode) codeView(r.ticket, signupsOpen); else boot();
      }
      catch (ex) { err.textContent = ex.message; btn.disabled = false; }
    };
  }

  // Second step of logging in, for accounts with two-step login.
  function codeView(ticket, signupsOpen) {
    root.innerHTML = `<div class="login"><div class="box">
      <div class="shieldwrap"><div class="glow"></div><div class="ring"></div><img src="/logo.png" alt="Lucent Shield"></div>
      <div class="pill"><span class="d"></span>Two-step login</div>
      <h1>Enter your code</h1>
      <p>Open your authenticator app and enter the 6-digit code for Lucent Shield.</p>
      <form id="codeForm" novalidate>
        <label class="lf">Code<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="9" required></label>
        <button class="btn" type="submit">Log in</button><div class="err" id="loginErr" role="alert"></div>
      </form>
      <div class="switch">Lost your phone? Enter one of your recovery codes instead.</div>
      <div class="switch"><button type="button" id="codeBack">Back to log in</button></div>
    </div></div>`;
    const f = document.getElementById("codeForm"); f.code.focus();
    document.getElementById("codeBack").onclick = () => loginView(signupsOpen);
    f.onsubmit = async (e) => {
      e.preventDefault();
      const err = document.getElementById("loginErr"); err.textContent = "";
      const btn = f.querySelector("button[type=submit]"); btn.disabled = true;
      try { await api("/api/login/code", { method: "POST", body: { ticket, code: f.code.value.trim() } }); boot(); }
      catch (ex) {
        err.textContent = ex.message; btn.disabled = false; f.code.select();
        if (/log in again/i.test(ex.message)) setTimeout(() => loginView(signupsOpen), 1800);
      }
    };
  }

  async function start() {
    await refresh();
    shell(); renderView();
    if (SHOW_TOUR) { SHOW_TOUR = false; setTimeout(watchGuide, 600); }
    if (polling) clearInterval(polling);
    polling = setInterval(poll, 20000);
  }

  async function boot() {
    try {
      const a = await api("/api/auth");
      ME = a.user; ADMIN = !!a.user?.admin;
      if (!ADMIN && VIEW === "admin") VIEW = "dashboard";
      if (!a.authed) loginView(a.signups); else start();
    }
    catch { root.innerHTML = `<div class="boot">Could not reach the server.</div>`; }
  }
  boot();
})();
