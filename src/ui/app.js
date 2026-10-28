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

  let ASSETS = [], ALERTS = [], UNREAD = 0, TOTAL_SCANS = 0, VIEW = "dashboard", polling = null;

  // ---------- shell ----------
  function shell() {
    const nav = [["dashboard", "home", "Dashboard"], ["assets", "assets", "Assets"], ["scans", "scans", "Scans"], ["reports", "reports", "Reports"], ["settings", "gear", "Settings"]];
    root.innerHTML = `<div class="app">
      <aside class="side">
        <div class="logo"><img src="/logo.svg" alt=""><div class="wm"><b>LUCENT</b><span>SHIELD</span></div></div>
        <nav class="nav">${nav.map(([v, i, l]) => `<a data-view="${v}" class="${VIEW === v ? "on" : ""}"><span class="ic">${ic(i)}</span>${l}</a>`).join("")}</nav>
        <div class="foot"><img src="/logo.svg" alt="">Built for a safer digital world.</div>
      </aside>
      <main class="main">
        <div class="topbar">
          <div class="crumbs">Scan · Detect · <b>Secure</b></div>
          <div class="sp"></div>
          <button class="iconbtn" id="bell">${ic("bell")}<span class="badge" id="bellBadge" hidden>0</span></button>
          <div class="user"><span class="av">BL</span><b>Bash Lucent</b></div>
        </div>
        <div class="content" id="view"></div>
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
    const checks = ["Checking headers & TLS", "Scanning for vulnerabilities", "Detecting leaked secrets", "Monitoring for threats", "Finalizing report"];
    return `<div class="hero ${st}">
      <div>
        <span class="live"><span class="dot"></span>Live protection</span>
        <h1>${words[st]}</h1>
        <p class="lead">${lead[st]}</p>
        <div class="scanbar">
          <div class="in">${ic("globe", 16)}<input id="quickUrl" placeholder="https://yoursite.com" maxlength="2000"></div>
          <button class="go" id="quickGo">Protect</button>
        </div>
        <div class="checks">${checks.map((c, i) => `<div class="chk ${i < 3 ? "done" : ""}"><span class="d">✓</span>${c}</div>`).join("")}</div>
      </div>
      <div class="herolock ${st}">
        <div class="halo"></div><div class="rings"></div>
        ${lockSvg("biglock")}
        <div class="statusword">${st === "secure" ? "SECURED" : st === "exposed" ? "EXPOSED" : st === "scanning" ? "SCANNING" : ""}</div>
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
    if (go) go.onclick = () => quickProtect(url.value.trim());
    if (url) url.onkeydown = (e) => { if (e.key === "Enter") quickProtect(url.value.trim()); };
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

  async function quickProtect(target) {
    if (!target) return;
    if (!confirm(`Confirm you own or are authorised to test:\n${target}`)) return;
    try {
      const { asset } = await api("/api/assets", { method: "POST", body: { name: target.replace(/^https?:\/\//, ""), kind: "web", target, authorized: true } });
      await refresh(); renderView();
      scanAsset(asset.id, true);
    } catch (ex) { alert(ex.message); }
  }

  // ---------- assets view ----------
  function assetsView() {
    return `<form class="add" id="addForm">
        <div class="field"><label>Name</label><input name="name" placeholder="My website" required maxlength="100"></div>
        <div class="field"><label>Kind</label><select name="kind">
          <option value="repo">Code repo (white box)</option><option value="web">Website (black box)</option><option value="artifact">Artifact (forensics)</option>
        </select></div>
        <div class="field"><label>Target</label><input name="target" placeholder="/path/to/repo  or  https://yoursite.com" required maxlength="2000"></div>
        <button class="btn" type="submit">Add & protect</button>
        <label class="auth" id="authRow" hidden><input type="checkbox" name="authorized"> I own this site or am authorised to test it.</label>
        <div class="err" id="addErr"></div>
      </form>
      <div class="grid" id="grid">${ASSETS.length ? ASSETS.map(cardHtml).join("") : `<div class="empty">No assets yet. Add one above.</div>`}</div>`;
  }

  function cardHtml(a) {
    const pills = [["c", a.counts.critical, "critical"], ["h", a.counts.high, "high"], ["m", a.counts.medium, "medium"], ["l", a.counts.low, "low"]]
      .filter(([, n]) => n).map(([cl, n, l]) => `<span class="pill ${cl}">${n} ${l}</span>`).join("");
    return `<div class="card s-${a.shield}" data-id="${a.id}">
      <span class="kind">${KIND_LABEL[a.kind] || a.kind}</span>
      <button class="mon ${a.monitor ? "on" : ""}" data-act="mon" title="${a.monitor ? "Monitoring on — click to pause" : "Paused — click to watch"}">${a.monitor ? "● watching" : "○ paused"}</button>
      <button class="del" data-act="del" title="Remove">✕</button>
      ${lockSvg("padlock")}
      <div class="name">${esc(a.name)}</div>
      <div class="target">${esc(a.target)}</div>
      <div class="state">${STATE_LABEL[a.shield]}</div>
      ${pills ? `<div class="counts">${pills}</div>` : ""}
      ${a.lastScanAt ? `<div class="scanned">scanned ${timeAgo(a.lastScanAt)}</div>` : ""}
      <div class="actions"><button data-act="scan">Scan now</button>${a.lastScanAt ? `<button data-act="view">Report</button>` : ""}</div>
    </div>`;
  }

  function wireAssets() {
    const form = document.getElementById("addForm"), authRow = document.getElementById("authRow"), kindSel = form.kind;
    const syncAuth = () => { authRow.hidden = kindSel.value !== "web"; };
    kindSel.onchange = syncAuth; syncAuth();
    form.onsubmit = async (e) => {
      e.preventDefault(); const err = document.getElementById("addErr"); err.textContent = "";
      try {
        const { asset } = await api("/api/assets", { method: "POST", body: { name: form.name.value.trim(), kind: kindSel.value, target: form.target.value.trim(), authorized: form.authorized?.checked || false } });
        form.reset(); syncAuth(); await refresh(); renderView(); scanAsset(asset.id, true);
      } catch (ex) { err.textContent = ex.message; }
    };
    document.getElementById("grid").onclick = (e) => {
      const card = e.target.closest(".card"); if (!card) return;
      const id = card.dataset.id, act = e.target.dataset.act;
      if (act === "scan") scanAsset(id); else if (act === "view") openReport(id); else if (act === "del") removeAsset(id); else if (act === "mon") toggleMonitor(id);
    };
  }

  function cardEl(id) { return document.querySelector(`.card[data-id="${id}"]`); }
  function setCard(id) { const a = ASSETS.find((x) => x.id === id), el = cardEl(id); if (a && el) el.outerHTML = cardHtml(a); }

  async function scanAsset(id, silent) {
    const el = cardEl(id);
    if (el) { el.className = "card s-scanning scan-sweep"; const s = el.querySelector(".state"); if (s) s.textContent = "Scanning…"; }
    if (VIEW === "dashboard") { const hs = document.querySelector(".herolock"); if (hs) hs.className = "herolock scanning"; }
    try {
      const { asset } = await api(`/api/assets/${id}/scan`, { method: "POST" });
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
    if (document.querySelector(".drawer")) return;
    let d; try { d = await api("/api/assets"); } catch { return; }
    const changed = JSON.stringify(d.assets.map((a) => [a.id, a.shield, a.counts])) !== JSON.stringify(ASSETS.map((a) => [a.id, a.shield, a.counts]));
    ASSETS = d.assets; TOTAL_SCANS = d.totalScans || 0; setBell(d.unread || 0);
    if (changed) { try { ALERTS = (await api("/api/alerts")).alerts; } catch {} renderView(); }
  }

  // ---------- login ----------
  function loginView() {
    root.innerHTML = `<div class="login"><div class="box"><img src="/logo.svg" alt=""><h1>Lucent Shield</h1><p>Enter your password to continue.</p>
      <form id="loginForm"><input type="password" name="password" placeholder="Password" autofocus required><button class="btn" type="submit">Unlock</button><div class="err" id="loginErr"></div></form></div></div>`;
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
