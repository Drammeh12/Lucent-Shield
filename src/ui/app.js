"use strict";
(() => {
  const root = document.getElementById("root");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      method: opts.method || "GET",
      headers: opts.body ? { "content-type": "application/json" } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(data.error || `Error ${res.status}`);
    return data;
  }

  const STATE_LABEL = {
    new: "Not scanned", scanning: "Scanning…", secure: "Protected",
    at_risk: "Needs attention", exposed: "Exposed",
  };

  function padlock() {
    return `<svg class="padlock" viewBox="0 0 120 140" aria-hidden="true">
      <ellipse class="glow" cx="60" cy="94" rx="54" ry="42" fill="var(--lock)"/>
      <path class="shackle" d="M38 58 V42 a22 22 0 0 1 44 0 V58"/>
      <rect class="body" x="26" y="58" width="68" height="62" rx="14"/>
      <circle class="keyhole" cx="60" cy="86" r="7"/>
      <rect class="stem" x="57" y="88" width="6" height="16" rx="3"/>
    </svg>`;
  }

  function countsPills(c) {
    if (!c) return "";
    const p = [];
    if (c.critical) p.push(`<span class="pill c">${c.critical} critical</span>`);
    if (c.high) p.push(`<span class="pill h">${c.high} high</span>`);
    if (c.medium) p.push(`<span class="pill m">${c.medium} medium</span>`);
    if (c.low) p.push(`<span class="pill l">${c.low} low</span>`);
    return p.join("");
  }

  function cardHtml(a) {
    return `<div class="card s-${a.shield}" data-id="${a.id}">
      <span class="kind">${esc(a.kind)}</span>
      <button class="del" title="Remove" data-act="del">✕</button>
      ${padlock()}
      <div class="name">${esc(a.name)}</div>
      <div class="target">${esc(a.target)}</div>
      <div class="state">${STATE_LABEL[a.shield] || a.shield}</div>
      <div class="counts">${countsPills(a.counts)}</div>
      <div class="actions">
        <button data-act="scan">Scan now</button>
        ${a.lastScanAt ? `<button data-act="view">View report</button>` : ""}
      </div>
    </div>`;
  }

  function overviewHtml(assets) {
    const total = assets.length;
    const secure = assets.filter((a) => a.shield === "secure").length;
    const exposed = assets.filter((a) => a.shield === "exposed").length;
    return `<div class="overview">
      <div class="ov total"><div class="n">${total}</div><div class="l">Assets</div></div>
      <div class="ov secure"><div class="n">${secure}</div><div class="l">Protected</div></div>
      <div class="ov exposed"><div class="n">${exposed}</div><div class="l">Exposed</div></div>
    </div>`;
  }

  function dashboardHtml(assets) {
    return `<div class="top">
        <span class="brand"><img src="/logo.svg" alt=""><b>Lucent Shield</b></span>
        <span class="tag">by Bash Lucent</span>
        <span class="spacer"></span>
        <button class="ghost" id="logout">Log out</button>
      </div>
      <div class="wrap">
        ${overviewHtml(assets)}
        <form class="add" id="addForm">
          <div class="field"><label>Name</label><input name="name" placeholder="My website" required maxlength="100"></div>
          <div class="field"><label>Kind</label>
            <select name="kind">
              <option value="repo">Code repo (white-box)</option>
              <option value="web">Website (black-box)</option>
              <option value="artifact">Artifact (forensics)</option>
            </select>
          </div>
          <div class="field"><label>Target</label><input name="target" placeholder="/path/to/repo  or  https://yoursite.com" required maxlength="2000"></div>
          <button class="btn" type="submit">Add &amp; protect</button>
          <label class="auth" id="authRow" hidden><input type="checkbox" name="authorized"> I own this site or am authorised to test it.</label>
          <div class="err" id="addErr"></div>
        </form>
        <div class="grid" id="grid">
          ${assets.length ? assets.map(cardHtml).join("") : `<div class="empty">No assets yet. Add a repo, a website you own, or an artifact to inspect.</div>`}
        </div>
      </div>`;
  }

  let ASSETS = [];

  async function loadDashboard() {
    const { assets } = await api("/api/assets");
    ASSETS = assets;
    root.innerHTML = dashboardHtml(assets);
    wireDashboard();
  }

  function wireDashboard() {
    document.getElementById("logout").onclick = async () => { await api("/api/logout", { method: "POST" }); boot(); };

    const form = document.getElementById("addForm");
    const authRow = document.getElementById("authRow");
    const kindSel = form.kind;
    const syncAuth = () => { authRow.hidden = kindSel.value !== "web"; };
    kindSel.onchange = syncAuth; syncAuth();

    form.onsubmit = async (e) => {
      e.preventDefault();
      const err = document.getElementById("addErr");
      err.textContent = "";
      const body = {
        name: form.name.value.trim(),
        kind: kindSel.value,
        target: form.target.value.trim(),
        authorized: form.authorized?.checked || false,
      };
      try {
        const { asset } = await api("/api/assets", { method: "POST", body });
        form.reset(); syncAuth();
        await loadDashboard();
        // auto-scan the new asset
        scanAsset(asset.id);
      } catch (ex) { err.textContent = ex.message; }
    };

    document.getElementById("grid").onclick = (e) => {
      const card = e.target.closest(".card");
      if (!card) return;
      const id = card.dataset.id;
      const act = e.target.dataset.act;
      if (act === "scan") scanAsset(id);
      else if (act === "view") openReport(id);
      else if (act === "del") removeAsset(id);
    };
  }

  function cardEl(id) { return document.querySelector(`.card[data-id="${id}"]`); }

  function setCardState(id, asset) {
    const el = cardEl(id);
    if (!el) return;
    el.outerHTML = cardHtml(asset);
  }

  async function scanAsset(id) {
    const el = cardEl(id);
    if (el) { el.className = "card s-scanning scan-sweep"; el.querySelector(".state").textContent = "Scanning…"; }
    try {
      const { asset } = await api(`/api/assets/${id}/scan`, { method: "POST" });
      ASSETS = ASSETS.map((a) => (a.id === id ? { ...a, ...asset } : a));
      setCardState(id, asset);
      refreshOverview();
    } catch (ex) {
      if (el) { el.classList.remove("scan-sweep"); el.querySelector(".state").textContent = "Scan failed"; }
    }
  }

  async function removeAsset(id) {
    if (!confirm("Remove this asset from Lucent Shield?")) return;
    await api(`/api/assets/${id}`, { method: "DELETE" });
    await loadDashboard();
  }

  function refreshOverview() {
    const bar = document.querySelector(".overview");
    if (bar) bar.outerHTML = overviewHtml(ASSETS);
  }

  async function openReport(id) {
    const { asset } = await api(`/api/assets/${id}`);
    const findings = asset.findings || [];
    const body = findings.length
      ? findings.map((f) => `<div class="finding">
          <div class="fh"><span class="sev ${f.severity}">${f.severity}</span><span class="ft">${esc(f.title)}</span></div>
          ${f.location ? `<div class="loc">${esc(f.location)}${f.line ? ":" + f.line : ""}</div>` : ""}
          ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ""}
          <div class="detail">${esc(f.detail)}</div>
          <div class="fix"><b>How to fix:</b> ${esc(f.remediation)}</div>
        </div>`).join("")
      : `<div class="clean-note">No issues found in the last scan. The shield is green. Keep scanning after changes — a clean scan is good news, not a guarantee.</div>`;

    const bg = document.createElement("div"); bg.className = "drawer-bg";
    const drawer = document.createElement("div"); drawer.className = "drawer";
    drawer.innerHTML = `<button class="x" id="closeDrawer">✕</button>
      <h2>${esc(asset.name)}</h2>
      <div class="sub">${esc(asset.target)} · scanned ${asset.lastScanAt ? new Date(asset.lastScanAt).toLocaleString() : "never"}</div>
      ${body}`;
    document.body.append(bg, drawer);
    const close = () => { bg.remove(); drawer.remove(); };
    bg.onclick = close;
    drawer.querySelector("#closeDrawer").onclick = close;
  }

  // ---------- login ----------
  function loginHtml() {
    return `<div class="login"><div class="box">
      <img src="/logo.svg" alt="">
      <h1>Lucent Shield</h1>
      <p>Enter your password to continue.</p>
      <form id="loginForm">
        <input type="password" name="password" placeholder="Password" autofocus required>
        <button class="btn" type="submit">Unlock</button>
        <div class="err" id="loginErr"></div>
      </form>
    </div></div>`;
  }

  function wireLogin() {
    const form = document.getElementById("loginForm");
    form.onsubmit = async (e) => {
      e.preventDefault();
      const err = document.getElementById("loginErr");
      err.textContent = "";
      try {
        await api("/api/login", { method: "POST", body: { password: form.password.value } });
        loadDashboard();
      } catch (ex) { err.textContent = ex.message; }
    };
  }

  async function boot() {
    try {
      const auth = await api("/api/auth");
      if (auth.required && !auth.authed) { root.innerHTML = loginHtml(); wireLogin(); }
      else loadDashboard();
    } catch {
      root.innerHTML = `<div class="boot">Could not reach the server.</div>`;
    }
  }

  boot();
})();
