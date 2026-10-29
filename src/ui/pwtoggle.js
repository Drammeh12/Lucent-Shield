/* Show or hide what you type in any password box (the eye button). */
(function () {
  "use strict";
  const svg = (d) => `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
  const OPEN = svg('<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>');
  const SHUT = svg('<path d="M3 3l18 18M10.6 5.1A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17.8 17.8 0 0 1-3.2 4.2M6.6 6.6A17.6 17.6 0 0 0 2 12s3.6 7 10 7a9.8 9.8 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>');
  function enhance(input) {
    if (input.dataset.pw || !input.parentNode) return;
    input.dataset.pw = "1";
    const cs = getComputedStyle(input);
    const wrap = document.createElement("span");
    wrap.className = "pw-wrap";
    // The box keeps its place: its outer spacing moves to the wrapper.
    wrap.style.marginTop = cs.marginTop; wrap.style.marginBottom = cs.marginBottom;
    wrap.style.marginLeft = cs.marginLeft; wrap.style.marginRight = cs.marginRight;
    if (cs.flexGrow && cs.flexGrow !== "0") wrap.style.flexGrow = cs.flexGrow;
    input.style.margin = "0";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "pw-eye";
    b.setAttribute("aria-label", "Show password");
    b.setAttribute("aria-pressed", "false");
    b.title = "Show password";
    b.innerHTML = OPEN;
    b.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      b.innerHTML = show ? SHUT : OPEN;
      b.setAttribute("aria-label", show ? "Hide password" : "Show password");
      b.setAttribute("aria-pressed", String(show));
      b.title = show ? "Hide password" : "Show password";
      input.focus();
      try { const n = input.value.length; input.setSelectionRange(n, n); } catch (e) { /* not supported */ }
    });
    wrap.appendChild(b);
  }
  const scan = (root) => { if (root.querySelectorAll) root.querySelectorAll('input[type="password"]').forEach(enhance); };
  const start = () => {
    scan(document);
    new MutationObserver((list) => {
      for (const m of list) for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.matches && n.matches('input[type="password"]')) enhance(n);
        scan(n);
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
