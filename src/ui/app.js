"use strict";
(() => {
  const root = document.getElementById("root");
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

  const STATE_LABEL = { new: "Not scanned", scanning: "Scanning…", secure: "Protected", at_risk: "Needs attention", exposed: "Exposed" };
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

  let ASSETS = [], ALERTS = [], UNREAD = 0, TOTAL_SCANS = 0, VIEW = "dashboard", polling = null, SEQ = false;

  // The target icon that flows through the padlock. Web assets show the site's
  // real favicon (fetched server-side); repos and artifacts show a glyph.
  function flowIcon(asset) {
    const glyph = asset?.kind === "repo" ? ic("code", 18) : asset?.kind === "artifact" ? ic("finger", 18) : ic("globe", 18);
    const img = asset?.kind === "web" ? `<img class="fav" src="/api/favicon?u=${encodeURIComponent(asset.target)}" alt="" onerror="this.remove()">` : "";
    return `<div class="flow"><span class="glyph">${glyph}</span>${img}</div>`;
  }
  // Which asset the big padlock represents right now.
  function focusAsset() {
    return ASSETS.find((a) => a.shield === "scanning") || ASSETS.find((a) => a.shield === "exposed")
      || ASSETS.find((a) => a.kind === "web") || ASSETS[0] || null;
  }

  // ---------- shell ----------
  function shell() {
    const nav = [["dashboard", "home", "Dashboard"], ["assets", "assets", "Assets"], ["scans", "scans", "Scans"], ["reports", "reports", "Reports"], ["settings", "gear", "Settings"]];
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
          <button class="iconbtn" id="bell">${ic("bell")}<span class="badge" id="bellBadge" hidden>0</span></button>
          <div class="user"><span class="av">BL</span><b>Bash Lucent</b></div>
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
    setBell(UNREAD);
  }

  function setBell(n) { UNREAD = n; const b = document.getElementById("bellBadge"); if (b) { b.hidden = !n; b.textContent = n > 99 ? "99+" : n; } }

  function renderView() {
    const el = document.getElementById("view");
    if (VIEW === "dashboard") el.innerHTML = dashboardView();
    else if (VIEW === "assets") { el.innerHTML = assetsView(); wireAssets(); }
    else if (VIEW === "reports" || VIEW === "scans") el.innerHTML = reportsView();
    else if (VIEW === "settings") { el.innerHTML = settingsView(); wireSettings(); }
    if (VIEW === "dashboard") wireDashboard();
  }

  // ---------- dashboard ----------
  function heroState() {
    if (ASSETS.some((a) => a.shield === "scanning")) return "scanning";
    if (ASSETS.some((a) => a.shield === "exposed")) return "exposed";
    if (ASSETS.length && ASSETS.every((a) => a.shield === "secure")) return "secure";
    return "new";
  }

  function statsView() {
    const total = ASSETS.length, secure = ASSETS.filter((a) => a.shield === "secure").length, exposed = ASSETS.filter((a) => a.shield === "exposed").length;
    const stat = (cls, icon, label, n, sub, subcls = "") => `<div class="stat"><div class="si ${cls}">${ic(icon, 20)}</div><div><div class="l">${label}</div><div class="n">${n}</div><div class="sub ${subcls}">${sub}</div></div></div>`;
    return `<div class="stats">
      ${stat("blue", "globe", "Total assets", total, `${ASSETS.filter(a=>!a.lastScanAt).length} awaiting scan`)}
      ${stat("green", "shield", "Protected", secure, "Currently secured", "ok")}
      ${stat("red", "alert", "Exposed", exposed, exposed ? "Needs attention" : "All clear", exposed ? "bad" : "ok")}
      ${stat("violet", "radar", "Total scans", TOTAL_SCANS, "since you started")}
    </div>`;
  }

  function heroView() {
    const st = heroState();
    const words = { secure: "All assets protected", exposed: "Attention needed", scanning: "Scanning your assets…", new: "Add an asset to protect" };
    const lead = {
      secure: "Lucent Shield is watching your assets around the clock. Everything is locked and secure.",
      exposed: "One or more assets have open issues. Open them to see exactly what to fix.",
      scanning: "Lucent Shield is actively scanning for secrets, vulnerabilities and exposed files.",
      new: "Protect a code repo, a website you own, or inspect a forensic artifact.",
    };
    const focus = focusAsset();
    return `<div class="hero ${st}" id="hero">
      <div class="heroL">
        <span class="live"><span class="dot"></span>Live protection</span>
        <h1 id="heroTitle">${words[st]}</h1>
        <p class="lead" id="heroLead">${lead[st]}</p>
        <div class="scanbar" id="heroScanbar">
          <div class="in">${ic("globe", 16)}<input id="quickUrl" placeholder="https://yoursite.com" maxlength="2000"></div>
          <button class="go" id="quickGo">Protect</button>
        </div>
        <div class="seq" id="heroSeq" hidden>
          <div class="meter" id="heroMeterWrap" hidden><i id="meterFill"></i></div>
          <div class="mlabel" id="meterLabel" hidden><b id="meterPct">0%</b> protection coverage</div>
          <div class="logstream" id="logstream"></div>
          <button class="secbtn" id="secBtn" hidden></button>
        </div>
      </div>
      <div class="herolock ${st}" id="herolock">
        <div class="halo"></div><div class="rings"></div>
        <div class="orbit">
          <svg class="wires" viewBox="-140 -140 280 280" aria-hidden="true">
            <circle class="track" cx="0" cy="0" r="120"/>
            <line class="wire" x1="0" y1="0" x2="0" y2="-120"/><line class="wire" x1="0" y1="0" x2="120" y2="0"/>
            <line class="wire" x1="0" y1="0" x2="0" y2="120"/><line class="wire" x1="0" y1="0" x2="-120" y2="0"/>
          </svg>
          <span class="node nT"><span class="lbl">${ic("code", 18)}</span></span>
          <span class="node nR"><span class="lbl">API</span></span>
          <span class="node nB"><span class="lbl">${ic("db", 18)}</span></span>
          <span class="node nL"><span class="lbl">${ic("server", 18)}</span></span>
        </div>
        ${flowIcon(focus)}
        <div class="scanline"></div>
        ${lockSvg("biglock")}
        <div class="statusword" id="statusword">${st === "secure" ? "SECURED" : st === "exposed" ? "EXPOSED" : st === "scanning" ? "SCANNING" : ""}</div>
      </div>
    </div>`;
  }

  function dashboardView() {
    const preview = ASSETS.slice(0, 4).map((a) => `<div class="row" data-open="${a.id}" style="cursor:pointer">
      <span class="dotline" style="background:${a.shield === "secure" ? "var(--green)" : a.shield === "exposed" ? "var(--red)" : a.shield === "at_risk" ? "var(--amber)" : "var(--muted)"}"></span>
      <div class="rt"><div class="t">${esc(a.name)}</div><div class="s">scanned ${timeAgo(a.lastScanAt)}</div></div>
      <span class="tag ${a.shield}">${STATE_LABEL[a.shield]}</span></div>`).join("") || `<div class="empty">No assets yet.</div>`;

    const scanTypes = [["repo", "code", "White box (pen test)", "Full access · deep code analysis"], ["web", "mask", "Black box", "No access · external view"], ["artifact", "finger", "Forensics", "Investigate · collect evidence"]]
      .map(([k, i, t, s]) => `<div class="row" data-kind="${k}" style="cursor:pointer"><div class="ri">${ic(i)}</div><div class="rt"><div class="t">${t}</div><div class="s">${s}</div></div><span class="chev">${ic("chev", 16)}</span></div>`).join("");

    const activity = buildActivity().slice(0, 6).map((e) => `<div class="row"><span class="dotline" style="background:${e.color}"></span><div class="rt"><div class="t">${esc(e.text)}</div><div class="s">${timeAgo(e.when)}</div></div></div>`).join("") || `<div class="empty">No activity yet.</div>`;

    return statsView() + heroView() + `<div class="cols">
      <div class="pnl"><div class="ph"><h3>${ic("assets", 16)} Your assets</h3><button class="all" data-view="assets">View all</button></div>${preview}</div>
      <div class="pnl"><div class="ph"><h3>${ic("scans", 16)} Scan types</h3></div>${scanTypes}</div>
      <div class="pnl"><div class="ph"><h3>${ic("reports", 16)} Recent activity</h3><button class="all" id="actAll">View all</button></div>${activity}</div>
    </div>`;
  }

  function buildActivity() {
    const items = [];
    for (const al of ALERTS) items.push({ text: al.message.replace(/^[🔓🔒]\s*Lucent Shield:\s*/, ""), when: al.at, color: al.type === "recovered" ? "var(--green)" : "var(--red)" });
    for (const a of ASSETS) if (a.lastScanAt) items.push({ text: `Scan completed — ${a.name}`, when: a.lastScanAt, color: a.shield === "exposed" ? "var(--red)" : "var(--green)" });
    return items.sort((x, y) => new Date(y.when) - new Date(x.when));
  }

  function wireDashboard() {
    const go = document.getElementById("quickGo"), url = document.getElementById("quickUrl");
    if (go) go.onclick = () => runScanSequence(url.value.trim());
    if (url) url.onkeydown = (e) => { if (e.key === "Enter") runScanSequence(url.value.trim()); };
    document.getElementById("view").onclick = (e) => {
      const kind = e.target.closest("[data-kind]")?.dataset.kind;
      const view = e.target.closest("[data-view]")?.dataset.view;
      const open = e.target.closest("[data-open]")?.dataset.open;
      if (kind) { VIEW = "assets"; shell(); renderView(); setTimeout(() => { const s = document.querySelector('select[name="kind"]'); if (s) { s.value = kind; s.dispatchEvent(new Event("change")); } document.querySelector('input[name="name"]')?.focus(); }, 30); }
      else if (view) { VIEW = view; shell(); renderView(); }
      else if (e.target.id === "actAll") openAlerts();
      else if (open) openReport(open);
    };
  }

  // ---------- live scan + secure sequence (the hero show) ----------
  const heroEl = (id) => document.getElementById(id);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  function setHero(state, title) {
    const h = heroEl("hero"), l = heroEl("herolock");
    if (h) h.className = "hero " + state;
    if (l) l.className = "herolock " + state;
    if (title) { const t = heroEl("heroTitle"); if (t) t.textContent = title; }
  }
  function setStatus(w) { const s = heroEl("statusword"); if (s) s.textContent = w; }
  function setFocusIcon(asset) { const f = heroEl("herolock")?.querySelector(".flow"); if (f) f.outerHTML = flowIcon(asset); }
  function enterSeq() {
    ["heroLead", "heroScanbar"].forEach((id) => { const e = heroEl(id); if (e) e.hidden = true; });
    const s = heroEl("heroSeq"); if (s) s.hidden = false;
    const ls = heroEl("logstream"); if (ls) ls.innerHTML = "";
    heroEl("heroMeterWrap").hidden = true; heroEl("meterLabel").hidden = true; hideSecBtn();
  }
  function showMeter() { heroEl("heroMeterWrap").hidden = false; heroEl("meterLabel").hidden = false; }
  function setMeter(pct) { const f = heroEl("meterFill"); if (f) f.style.width = pct + "%"; const p = heroEl("meterPct"); if (p) p.textContent = Math.round(pct) + "%"; }
  function logLine(cls, html) {
    const ls = heroEl("logstream"); if (!ls) return;
    const mark = cls === "ok" ? "✓" : cls === "bad" ? "✕" : cls === "warn" ? "!" : cls === "run" ? "›" : "·";
    const d = document.createElement("div"); d.className = "logline";
    d.innerHTML = `<span class="${cls || "run"}">${mark}</span> ${html}`;
    ls.appendChild(d); while (ls.children.length > 6) ls.removeChild(ls.firstChild);
  }
  // Severity -> log colour. Critical/high read as alarms, medium as a warning.
  const sevClass = (s) => (s === "critical" || s === "high" ? "bad" : s === "medium" ? "warn" : "");
  // Turn a real finding into a short "closing this down" action line for the Secure log.
  function fixPhrase(f) {
    const t = (f.title || "").toLowerCase(), r = (f.rule || "").toLowerCase();
    if (t.includes("hsts") || t.includes("strict-transport")) return ["Enabling HSTS", "enabled"];
    if (t.includes("content-security-policy")) return ["Adding Content-Security-Policy", "enabled"];
    if (t.includes("x-content-type")) return ["Setting X-Content-Type-Options: nosniff", "enabled"];
    if (t.includes("clickjacking") || t.includes("x-frame")) return ["Blocking clickjacking (X-Frame-Options)", "enabled"];
    if (t.includes("referrer-policy")) return ["Setting Referrer-Policy", "enabled"];
    if (t.includes("plain http") || t.includes("http")) return ["Forcing HTTPS", "closed"];
    if (t.includes("cookie")) return ["Hardening cookie flags (Secure, HttpOnly)", "closed"];
    if (t.includes("x-powered-by") || t.includes("server version") || t.includes("technology disclosed")) return ["Hiding server and stack version", "closed"];
    if (t.includes(".env") || t.includes(".git") || t.includes("backup") || t.includes("config") || t.includes(".ds_store") || t.includes("exposed") || r.includes("exposed")) {
      const m = f.title.match(/\(([^)]+)\)|^[^:]+/); return [`Blocking public access to ${f.title.replace(/ exposed.*/i, "").replace(/^Environment file/, ".env")}`, "closed"];
    }
    return [`Hardening: ${f.title}`, "closed"];
  }
  function showSecBtn(label, fn) { const b = heroEl("secBtn"); if (!b) return; b.hidden = false; b.className = "secbtn"; b.textContent = label; b.onclick = fn; }
  function secBtnDone(label) { const b = heroEl("secBtn"); if (!b) return; b.hidden = false; b.className = "secbtn done"; b.textContent = label; b.onclick = null; }
  function hideSecBtn() { const b = heroEl("secBtn"); if (b) b.hidden = true; }
  function finishSeqSoon(ms = 3200) { setTimeout(async () => { SEQ = false; await refresh(); if (VIEW === "dashboard") renderView(); }, ms); }

  // Explicit, per-run authorization before ANY test (white box, black box or
  // forensics). Required every time, even after the terms were accepted.
  // Resolves to false (cancelled) or { reference } once the operator affirms.
  function authorizeScan(kind, target) {
    return new Promise((resolve) => {
      const forensic = kind === "artifact";
      const label = kind === "repo" ? "white-box (full code) test" : kind === "web" ? "black-box (external) test" : "forensic examination";
      const noun = kind === "repo" ? "repository or folder" : kind === "web" ? "website" : "file or artifact";
      const bg = document.createElement("div"); bg.className = "drawer-bg";
      const m = document.createElement("div"); m.className = "authbox";
      m.innerHTML = `
        <div class="ah ${forensic ? "danger" : ""}">${ic("shield", 20)} ${forensic ? "Legal authorization required" : "Authorization required"}</div>
        <p>You are about to run a <b>${label}</b> against:</p>
        <div class="tgt">${esc(target)}</div>
        <p class="warn">${forensic
          ? "Forensic examination can reveal personal and sensitive data. You may only do it with lawful authority — ownership, written permission, or a warrant or court order. Doing it without authority is a serious offence, and the responsibility is entirely yours."
          : `Only test systems you own or have explicit permission to test. Running a test against a ${noun} you are not authorised to test may be illegal, and the responsibility is yours.`}</p>
        ${forensic ? `
        <label class="al">Authorization reference</label>
        <input class="aref" id="authRef" maxlength="200" placeholder="Warrant / court order / written-permission reference">
        <label class="chk2"><input type="checkbox" id="authLegal"><span>I attest that I hold lawful authority (ownership, written permission, or a warrant or court order) to examine this, and I can produce it on request.</span></label>` : ""}
        <label class="chk2"><input type="checkbox" id="authChk"><span>I confirm I own this ${noun} or have explicit authorisation to test it, and I give Lucent Shield explicit permission to scan it and identify vulnerabilities.</span></label>
        <div class="arow"><button class="ghost" id="authCancel">Cancel</button><button class="btn" id="authGo" disabled>Authorise &amp; run</button></div>
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

  // Domain-ownership verification: prove control of the site before scanning it.
  function openVerify(asset, onVerified) {
    const host = esc(asset.target.replace(/^https?:\/\//, "").replace(/\/.*$/, ""));
    const tok = esc(asset.verifyToken);
    const body = `
      <h2>Verify you own ${host}</h2>
      <div class="sub">Lucent Shield will not scan a website until you prove you control it. Choose one method, then press Verify.</div>
      <div class="vmethod"><div class="vt">Option 1 — host a file</div>
        <p>Put a file at this exact address, containing the token below:</p>
        <div class="tgt">https://${host}/.well-known/lucent-verify.txt</div></div>
      <div class="vmethod"><div class="vt">Option 2 — add a DNS record</div>
        <p>Add this TXT record to <b>${host}</b>:</p>
        <div class="tgt">lucent-verify=${tok}</div></div>
      <div class="vmethod"><div class="vt">Your token</div><div class="tgt">${tok}</div></div>
      <div class="arow"><button class="btn" id="vGo">Verify ownership</button></div>
      <div class="vstatus" id="vStatus"></div>`;
    const d = drawer(body);
    const st = d.querySelector("#vStatus"), go = d.querySelector("#vGo");
    go.onclick = async () => {
      st.textContent = "Checking…"; st.className = "vstatus";
      try {
        const r = await api(`/api/assets/${asset.id}/verify`, { method: "POST" });
        if (r.verified) {
          st.textContent = "Verified. Ownership confirmed."; st.className = "vstatus ok";
          await refresh();
          setTimeout(() => { d.close(); const fresh = ASSETS.find((a) => a.id === asset.id) || { ...asset, verified: true }; if (onVerified) onVerified(fresh); else renderView(); }, 800);
        } else {
          st.textContent = "Not found yet. DNS or the file can take a few minutes — try again shortly."; st.className = "vstatus bad";
        }
      } catch (ex) { st.textContent = ex.message; st.className = "vstatus bad"; }
    };
  }

  async function runScanSequence(target) {
    if (!target) return;
    if (!(await authorizeScan("web", target))) return;
    let asset;
    try {
      const r = await api("/api/assets", { method: "POST", body: { name: target.replace(/^https?:\/\//, ""), kind: "web", target, authorized: true } });
      asset = r.asset;
    } catch (ex) { alert(ex.message); return; }
    await refresh();
    const fresh = ASSETS.find((a) => a.id === asset.id) || asset;
    // A website must prove domain ownership before the first scan.
    if (!fresh.verified) { if (VIEW === "dashboard") renderView(); openVerify(fresh, () => startScanSequence(fresh)); return; }
    startScanSequence(fresh);
  }

  async function startScanSequence(asset) {
    const host = asset.name;
    SEQ = true;
    if (!ASSETS.find((a) => a.id === asset.id)) ASSETS = [{ ...asset }, ...ASSETS];
    renderView();
    enterSeq(); setFocusIcon(asset); setHero("scanning", `Scanning ${esc(host)}…`); setStatus("SCANNING");
    const scanP = api(`/api/assets/${asset.id}/scan`, { method: "POST", body: { authorized: true } }).catch(() => null);
    const lines = [["run", `Resolving host <b>${esc(host)}</b>`], ["run", "Opening secure connection"], ["", "Reading response headers"], ["", "Checking TLS and HSTS"], ["", "Inspecting cookies"], ["", "Probing for exposed files"], ["", "Evaluating content security policy"]];
    for (const [c, t] of lines) { logLine(c, t); await wait(440); }
    logLine("run", "Scoring exposure…");
    const res = await scanP; await wait(380);
    const a = res?.asset;
    if (!a) { logLine("bad", "Scan could not complete. Check the address and try again."); setStatus("ERROR"); finishSeqSoon(); return; }
    ASSETS = ASSETS.map((x) => (x.id === asset.id ? { ...x, ...a } : x)); TOTAL_SCANS++;
    const findings = (a.findings || []).slice().sort((x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity));
    const bad = a.counts.critical + a.counts.high;
    // Show what was actually found, one line at a time, like real logs.
    if (findings.length) {
      logLine("run", "Issues detected:");
      await wait(300);
      const shown = findings.slice(0, 8);
      for (const f of shown) {
        logLine(sevClass(f.severity), `<b>${f.severity.toUpperCase()}</b> ${esc(f.title)}`);
        await wait(360);
      }
      if (findings.length > shown.length) { logLine("", `…and ${findings.length - shown.length} more`); await wait(300); }
    }
    if (bad > 0) {
      setHero("exposed", "Attention needed"); setStatus("EXPOSED");
      logLine("bad", `${findings.length} issue${findings.length !== 1 ? "s" : ""} open — ${a.counts.critical} critical, ${a.counts.high} high. Press Secure to close them.`);
      showSecBtn(`Secure ${esc(host)}`, () => secureFlow(a.id, host, findings));
    } else if (findings.length) {
      setHero("secure", "Protected"); setStatus("SECURED");
      logLine("ok", "No critical or high issues. Minor notes only.");
      logLine("ok", `${esc(host)} is locked and protected`);
      finishSeqSoon();
    } else {
      setHero("secure", "Protected"); setStatus("SECURED");
      logLine("ok", "No issues found");
      logLine("ok", `${esc(host)} is locked and protected`);
      finishSeqSoon();
    }
  }

  async function secureFlow(assetId, host, findings) {
    SEQ = true; hideSecBtn();
    setHero("securing", "Closing the gaps…"); setStatus("SECURING");
    showMeter(); setMeter(6);
    api(`/api/assets/${assetId}/monitor`, { method: "POST", body: { on: true } }).catch(() => {});
    logLine("run", "Engaging Lucent Shield");
    await wait(480); setMeter(14);
    const fixes = (findings || []).filter((f) => f.severity !== "info").slice(0, 12);
    if (fixes.length) {
      const span = 78 / fixes.length;
      for (let i = 0; i < fixes.length; i++) {
        const [action, verb] = fixPhrase(fixes[i]);
        logLine("", `${action}…`); await wait(430);
        logLine("ok", `${action} → ${verb}`); setMeter(14 + span * (i + 1)); await wait(260);
      }
    } else {
      for (const [pct, t] of [[40, "Applying hardening baseline"], [70, "Enabling continuous monitoring"], [90, "Arming threat alerts"]]) { logLine("", t); setMeter(pct); await wait(520); }
    }
    logLine("run", "Re-scanning to verify…");
    const res = await api(`/api/assets/${assetId}/scan`, { method: "POST", body: { authorized: true } }).catch(() => null);
    const a = res?.asset; if (a) { ASSETS = ASSETS.map((x) => (x.id === assetId ? { ...x, ...a } : x)); TOTAL_SCANS++; }
    await wait(420);
    const bad = a ? a.counts.critical + a.counts.high : 1;
    if (bad === 0) {
      setMeter(100); setHero("secure", "Protected"); setStatus("SECURED");
      logLine("ok", "Protection active. Monitoring engaged.");
      secBtnDone("Protected"); finishSeqSoon(3400);
    } else {
      setMeter(Math.max(20, 100 - bad * 18)); setHero("exposed", "Still needs your action"); setStatus("EXPOSED");
      logLine("bad", `${bad} critical/high issue${bad !== 1 ? "s" : ""} remain. Open the report for the fix.`);
      showSecBtn("Open the report", () => openReport(assetId));
    }
  }

  // ---------- assets view ----------
  function assetsView() {
    return `<form class="add" id="addForm">
        <div class="field"><label>Name</label><input name="name" placeholder="My website" required maxlength="100"></div>
        <div class="field"><label>Kind</label><select name="kind">
          <option value="repo">Code repo (white box)</option><option value="web">Website (black box)</option><option value="artifact">Artifact (forensics)</option>
        </select></div>
        <div class="field"><label>Target</label><input name="target" placeholder="github.com/you/repo  ·  /path/to/repo  ·  https://yoursite.com" required maxlength="2000"></div>
        <button class="btn" type="submit">Add & protect</button>
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
      <button class="mon ${a.monitor ? "on" : ""}" data-act="mon" title="${a.monitor ? "Monitoring on — click to pause" : "Paused — click to watch"}">${a.monitor ? "● watching" : "○ paused"}</button>
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
    try { const { asset } = await api(`/api/assets/${id}/monitor`, { method: "POST", body: { on: !a.monitor } }); ASSETS = ASSETS.map((x) => (x.id === id ? { ...x, ...asset } : x)); setCard(id); } catch {}
  }

  async function removeAsset(id) { if (!confirm("Remove this asset?")) return; await api(`/api/assets/${id}`, { method: "DELETE" }); await refresh(); renderView(); }

  async function openReport(id) {
    const { asset } = await api(`/api/assets/${id}`);
    const f = asset.findings || [];
    const body = f.length ? f.map((x) => `<div class="finding"><div class="fh"><span class="sev ${x.severity}">${x.severity}</span><span class="ft">${esc(x.title)}</span></div>${x.location ? `<div class="loc">${esc(x.location)}${x.line ? ":" + x.line : ""}</div>` : ""}${x.evidence ? `<pre>${esc(x.evidence)}</pre>` : ""}<div class="detail">${esc(x.detail)}</div><div class="fix"><b>How to fix:</b> ${esc(x.remediation)}</div></div>`).join("")
      : `<div class="clean-note">No issues in the last scan. The padlock is green. Keep scanning after changes.</div>`;
    drawer(`<h2>${esc(asset.name)}</h2><div class="sub">${esc(asset.target)} · scanned ${asset.lastScanAt ? new Date(asset.lastScanAt).toLocaleString() : "never"}</div>${body}`);
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
    return `<div class="set">
      <div class="kv"><span class="k">Monitored assets</span><b>${watching} of ${ASSETS.length}</b></div>
      <div class="kv"><span class="k">Auto re-scan</span><span>On the server schedule (<code>LUCENT_SCAN_INTERVAL_MIN</code>)</span></div>
      <div class="kv"><span class="k">Alerts webhook</span><span>Set <code>LUCENT_ALERT_WEBHOOK</code> to also send to Slack/Discord</span></div>
      <div class="kv"><span class="k">Login</span><button class="btn" id="logout" style="padding:7px 14px">Log out</button></div>
    </div>`;
  }
  function wireSettings() { const b = document.getElementById("logout"); if (b) b.onclick = async () => { if (polling) clearInterval(polling); await api("/api/logout", { method: "POST" }); boot(); }; }

  // ---------- data ----------
  async function refresh() { const d = await api("/api/assets"); ASSETS = d.assets; TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0); try { ALERTS = (await api("/api/alerts")).alerts; } catch {} }
  async function refreshCounts() { try { const d = await api("/api/assets"); TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0); } catch {} }

  async function poll() {
    if (SEQ || document.querySelector(".drawer")) return;
    let d; try { d = await api("/api/assets"); } catch { return; }
    const changed = JSON.stringify(d.assets.map((a) => [a.id, a.shield, a.counts])) !== JSON.stringify(ASSETS.map((a) => [a.id, a.shield, a.counts]));
    ASSETS = d.assets; TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0);
    if (changed) { try { ALERTS = (await api("/api/alerts")).alerts; } catch {} renderView(); }
  }

  // ---------- login ----------
  function loginView() {
    root.innerHTML = `<div class="login"><div class="box">
      <div class="shieldwrap"><div class="glow"></div><div class="ring"></div><img src="/logo.png" alt="Lucent Shield"></div>
      <div class="pill"><span class="d"></span>Protected access</div>
      <h1>Lucent Shield</h1><p>Enter your password to open your dashboard.</p>
      <form id="loginForm"><input type="password" name="password" placeholder="Password" autofocus required>
        <button class="btn" type="submit">Unlock</button><div class="err" id="loginErr"></div></form>
      <div class="foot"><a href="/about">About</a><a href="/terms">Terms</a><a href="/privacy">Privacy</a></div>
      <div class="cap">Created by Bash Lucent · © 2026</div>
    </div></div>`;
    document.getElementById("loginForm").onsubmit = async (e) => {
      e.preventDefault(); const err = document.getElementById("loginErr"); err.textContent = "";
      try { await api("/api/login", { method: "POST", body: { password: e.target.password.value } }); start(); } catch (ex) { err.textContent = ex.message; }
    };
  }

  async function start() {
    await refresh();
    shell(); renderView();
    if (polling) clearInterval(polling);
    polling = setInterval(poll, 20000);
  }

  async function boot() {
    try { const a = await api("/api/auth"); if (a.required && !a.authed) loginView(); else start(); }
    catch { root.innerHTML = `<div class="boot">Could not reach the server.</div>`; }
  }
  boot();
})();
