/*
 * Lucent Shield's guided video: the presenter explains, the phone shows each
 * step being done. Opened with LucentTour.open() from the log in and sign-up
 * pages, the top bar, and once automatically after a new account is created.
 */
(function () {
  "use strict";

  function scenes() {
    const el = window.Guide.el;
    const bar = (title, right) => el("div", { class: "ls-bar" }, el("img", { src: "/guide-mark.png", alt: "" }), el("span", { text: title || "Lucent Shield" }), right ? el("span", { class: "r", text: right }) : null);
    const body = (...kids) => el("div", { class: "ls-body" }, ...kids);
    const btn = (text, cls = "") => el("div", { class: `ls-btn ${cls}`, text });
    const field = (label) => { const v = el("div", { class: "ls-input" }); return { box: el("label", { class: "ls-field" }, el("span", { text: label }), v), v }; };
    const hidden = (n) => { n.classList.add("g-hide"); return n; };
    const row = (dot, title, meta, tag, tagCls) => el("div", { class: "ls-row" }, el("span", { class: `ls-dot ${dot}` }), el("div", {}, el("div", { text: title }), meta ? el("div", { class: "m", text: meta }) : null), tag ? el("span", { class: `ls-tag e ${tagCls || ""}`, text: tag }) : null);
    const log = () => el("div", { class: "ls-log" });
    const line = (cls, text) => el("div", {}, el("span", { class: cls, text: { ok: "✓ ", bad: "✕ ", warn: "! ", run: "› " }[cls] || "· " }), text);
    const check = (text) => el("div", { class: "ls-check" }, el("i"), el("span", { text }));
    const steps = (n) => el("div", { class: "ls-steps" }, el("span", { class: n > 1 ? "done" : "on", text: "1 Scan" }), el("span", { class: n === 2 ? "on" : n > 2 ? "done" : "", text: "2 Protect" }));
    function lock(state) {
      const w = el("div", { class: `ls-lock ${state}` });
      w.innerHTML = `<div class="orb"><i>&lt;&gt;</i><i>API</i><i>DB</i><i>SRV</i></div>
        <svg viewBox="0 0 160 180" aria-hidden="true">
          <path class="sh" d="M80 6 L146 30 V84 C146 128 118 160 80 174 C42 160 14 128 14 84 V30 Z"/>
          <g transform="translate(35 40) scale(.75)">
            <path class="sk" d="M38 58 V42 a22 22 0 0 1 44 0 V58"/>
            <rect class="bd" x="26" y="58" width="68" height="62" rx="14"/>
            <circle class="kh" cx="60" cy="86" r="7"/><rect class="kh" x="57" y="88" width="6" height="16" rx="3"/>
          </g></svg>`;
      return w;
    }

    return [
      {
        title: "Welcome",
        pose: "wave",
        say: "Hi, welcome to Lucent Shield by Bash Lucent! It finds the security holes in code and websites you own, shows you exactly how to fix each one, then keeps watching so you know the moment something changes. Let me show you every part of it.",
        async build(screen, api) {
          const hero = el("div", { class: "ls-hero" },
            el("img", { src: "/guide-mark.png", alt: "" }),
            el("h3", { text: "Lucent Shield" }),
            el("p", { text: "Scan · Detect · Secure" }),
            hidden(el("div", { class: "ls-toast", text: "Security you can actually see" })));
          screen.append(hero);
          await api.wait(1500);
          await api.reveal(hero.lastChild);
        },
      },
      {
        title: "Create your account",
        pose: "point",
        say: "First, create your account. Type your name, your email and a password of at least ten characters. Tick the box to agree to the Terms, which also means you promise to scan only what you own or are allowed to test. Then press Create account.",
        async build(screen, api) {
          const name = field("Name"), email = field("Email"), pass = field("Password");
          const agree = check("I agree to the Terms and will only scan what I own or am authorised to test.");
          const go = btn("Create account");
          screen.append(bar(), body(el("div", { class: "ls-h", text: "Create your account" }), name.box, email.box, pass.box, agree, go));
          await api.wait(700);
          await api.type(name.v, "Amaka Obi", 60);
          await api.type(email.v, "amaka@myshop.ng", 45);
          await api.type(pass.v, "••••••••••••", 40);
          await api.tap(agree); agree.classList.add("on");
          await api.tap(go);
        },
      },
      {
        title: "Secure it with your phone",
        pose: "point",
        say: "Straight after creating your account, you secure it with your phone. Install Google Authenticator from the Play Store on Android, or the App Store on iPhone. Open it, tap plus, and scan the QR code on your screen. Type the six-digit code it shows, and save your recovery codes. From then on, logging in needs your password and that code.",

        async build(screen, api) {
          const on = btn("Activate");
          screen.append(bar("Settings"), body(el("div", { class: "ls-h", text: "Turn on your authenticator" }), el("p", { class: "ls-p", text: "1. Install Google Authenticator  2. Tap +  3. Scan the code  4. Type the 6 digits" }), on));
          await api.wait(1100);
          await api.tap(on);
          const code = el("div", { class: "ls-code" }, ..."482913".split("").map(() => el("span")));
          screen.querySelector(".ls-body").append(hidden(el("div", { class: "ls-qr" }, el("div"))), hidden(code));
          await api.reveal(screen.querySelector(".ls-qr"));
          await api.reveal(code);
          for (const [i, d] of [..."482913"].entries()) { code.children[i].textContent = d; await api.wait(140); }
          screen.querySelector(".ls-body").append(hidden(el("div", { class: "ls-toast", text: "✓ Account secured" })));
          await api.reveal(screen.querySelector(".ls-toast"));
        },
      },
      {
        title: "Your dashboard",
        pose: "point",
        say: "This is your dashboard. At the top: how many assets you have, how many are protected, how many are exposed with serious problems, and how many scans you have run. An asset is simply something you protect: your code, or your website.",
        async build(screen, api) {
          const stats = el("div", { class: "ls-stats" }, ...[["0", "Assets"], ["0", "Protected"], ["0", "Exposed"], ["0", "Scans run"]].map(([n, l]) => el("div", { class: "ls-stat" }, el("b", { text: n }), el("span", { text: l }))));
          screen.append(bar("Dashboard", "Amaka"), body(stats, el("div", { class: "ls-h", text: "Scan, then protect" }), steps(1), lock(""), el("div", { class: "ls-word", text: "Waiting for your first scan" })));
          await api.wait(1200);
          for (const s of stats.children) { await api.tap(s); }
          api.hideTap();
        },
      },
      {
        title: "Step 1: choose a scan",
        pose: "think",
        say: "Step one is the scan. Choose White box to check your code: paste your GitHub repository address, and Lucent Shield looks for leaked passwords and keys, risky code and outdated packages. Choose Black box to check your live website from the outside, the way a visitor or an attacker sees it.",
        async build(screen, api) {
          const white = el("div", { class: "ls-type" }, el("b", { text: "White box" }), "Your code");
          const black = el("div", { class: "ls-type on" }, el("b", { text: "Black box" }), "Your website");
          const input = el("div", { class: "ls-input" });
          screen.append(bar("Dashboard"), body(steps(1), el("div", { class: "ls-types" }, white, black), input, btn("Scan code")));
          await api.wait(800);
          await api.tap(white); white.classList.add("on"); black.classList.remove("on");
          await api.type(input, "https://github.com/amaka/myshop", 40);
          await api.wait(600);
          await api.tap(black); black.classList.add("on"); white.classList.remove("on");
          input.textContent = "";
          screen.querySelector(".ls-btn").textContent = "Scan website";
          await api.type(input, "https://myshop.ng", 55);
        },
      },
      {
        title: "Your permission, every time",
        pose: "point",
        say: "Before any scan, Lucent Shield asks for your permission. You confirm that you own it, or are allowed to test it. This is recorded with the date and time, every single time, so there is always proof that the test was allowed.",
        async build(screen, api) {
          const c = check("I own this website or have explicit authorisation to test it, and I give Lucent Shield permission to scan it.");
          const go = btn("Authorise & scan");
          screen.append(bar("Dashboard"), body(el("div", { class: "ls-modal" }, el("b", { text: "Authorization required" }), el("div", { class: "ls-mono", text: "https://myshop.ng" }), c, go, el("span", { text: "Recorded with a timestamp." }))));
          await api.wait(1400);
          await api.tap(c); c.classList.add("on");
          await api.tap(go);
        },
      },
      {
        title: "Prove you own the website",
        pose: "think",
        say: "For a website, you prove you own it once, so nobody can use Lucent Shield to scan someone else's site. Pick one way. Upload a small file we give you to your website, or add a short text record in your domain's DNS settings. Not technical? Choose Ask our team, and a person will check it with you. You can also email the steps to your developer.",
        async build(screen, api) {
          const file = el("div", { class: "on" }, el("b", { text: "Upload a file" }), "Change your site's files");
          const dns = el("div", {}, el("b", { text: "Add a DNS record" }), "Change domain settings");
          const ask = el("div", {}, el("b", { text: "Ask our team" }), "A person checks it");
          const how = el("div", { class: "ls-mono", text: "myshop.ng/.well-known/lucent-verify.txt" });
          const verify = btn("Verify ownership");
          screen.append(bar("Verify myshop.ng"), body(el("div", { class: "ls-seg three" }, file, dns, ask), btn("Download lucent-verify.txt", "ghost"), how, verify));
          await api.wait(1200);
          await api.tap(dns); dns.classList.add("on"); file.classList.remove("on");
          how.textContent = "TXT  @  lucent-verify=7f3a…";
          await api.wait(900);
          await api.tap(file); file.classList.add("on"); dns.classList.remove("on");
          how.textContent = "myshop.ng/.well-known/lucent-verify.txt";
          await api.tap(verify);
          screen.querySelector(".ls-body").append(hidden(el("div", { class: "ls-toast", text: "✓ Verified. You own this site." })));
          await api.reveal(screen.querySelector(".ls-toast"));
        },
      },
      {
        title: "Watch the scan live",
        pose: "point",
        say: "Now the scan runs, and you watch it live. Each check appears as it happens, then every problem it finds, coloured by how serious it is: red for critical and high, amber for medium. The padlock stays open and red while your site is exposed.",
        async build(screen, api) {
          const l = log();
          const lk = lock("red");
          const word = el("div", { class: "ls-word", text: "SCANNING" });
          screen.append(bar("Dashboard"), body(steps(1), lk, word, l));
          const lines = [["run", "Resolving myshop.ng"], ["", "Checking HTTPS and the certificate"], ["", "Reading the security headers"], ["", "Looking for files that should never be public"], ["run", "3 issues found:"], ["bad", "HIGH  .env file is public"], ["warn", "MEDIUM  Missing Content-Security-Policy"], ["", "LOW  Missing clickjacking protection"]];
          for (const [c, t] of lines) { l.append(hidden(line(c, t))); await api.reveal(l.lastChild, 520); }
          word.textContent = "EXPOSED";
        },
      },
      {
        title: "See exactly how to fix it",
        pose: "point",
        say: "Tap See the fixes. Every problem shows where it is, what it means, and the exact steps to fix it. You can also download a full Security Assessment Report as a PDF, with an executive summary, risk scores, and a fix-by date for each issue. Share it with your developer or your client.",
        async build(screen, api) {
          const fix = el("div", { class: "ls-row" }, el("span", { class: "ls-tag r", text: "HIGH" }), el("div", {}, el("div", { text: ".env file is public" }), el("div", { class: "m", text: "Fix: block /.env on your server, then rotate the keys in it" })));
          const pdf = btn("Full assessment report (PDF)");
          screen.append(bar("Report"), body(fix, el("div", { class: "ls-row" }, el("span", { class: "ls-tag a", text: "MED" }), el("div", {}, el("div", { text: "Missing Content-Security-Policy" }), el("div", { class: "m", text: "Fix: add a CSP header" }))), pdf));
          await api.wait(1300);
          await api.tap(pdf);
          const doc = hidden(el("div", { class: "ls-doc" }, el("div", { class: "cv", text: "Security Assessment Report" }), el("b", { text: "Overall risk: High" }), el("div", { class: "ln" }), el("div", { class: "ln s" }), el("div", { class: "ln" })));
          screen.querySelector(".ls-body").append(doc);
          await api.reveal(doc);
        },
      },
      {
        title: "Step 2: Protect",
        pose: "cheer",
        say: "Step two: press Protect. You give permission once for Lucent Shield to keep checking your site. The padlock closes on the shield, your site's icon flows through it, and your code, API, database and server start circling it. That means protection is live.",
        async build(screen, api) {
          const lk = lock("red");
          const word = el("div", { class: "ls-word", text: "EXPOSED" });
          const prot = btn("Protect");
          screen.append(bar("Dashboard"), body(steps(2), lk, word, prot));
          await api.wait(1200);
          await api.tap(prot);
          lk.className = "ls-lock amber closed";
          word.textContent = "PROTECTED";
          await api.wait(1400);
          lk.className = "ls-lock green closed";
          word.textContent = "SECURED";
          screen.querySelector(".ls-body").append(hidden(el("div", { class: "ls-toast", text: "Protection is live" })));
          await api.reveal(screen.querySelector(".ls-toast"));
        },
      },
      {
        title: "Green, amber and red",
        pose: "think",
        say: "What the colours mean. Red and open: serious problems and no protection. Amber and closed: protected and watched, but some critical or high fixes are still waiting. Green and closed: protected, and nothing serious is open. Fix the issues and scan again to turn it green.",
        async build(screen, api) {
          const items = [["red", "Red and open: exposed, not protected"], ["amber closed", "Amber and closed: protected, fixes still to make"], ["green closed", "Green and closed: protected and secure"]]
            .map(([c, t]) => hidden(el("div", { class: "ls-row ls-mini" }, lock(c), el("span", { text: t }))));
          screen.append(bar("Dashboard"), body(...items));
          for (const r of items) await api.reveal(r, 900);
        },
      },
      {
        title: "Alerts and recent activity",
        pose: "point",
        say: "While protected, Lucent Shield checks again every few hours. If something changes, like a file becoming public, a setting being weakened, or a new vulnerable package, you get an alert on the bell. Recent activity lists everything that really happened, in order.",
        async build(screen, api) {
          const rows = [row("r", "myshop.ng is now EXPOSED: 1 high", "just now"), row("g", "Protection turned on for myshop.ng", "2h ago"), row("c", "Ownership of myshop.ng proven", "2h ago"), row("", "Added myshop.ng", "2h ago")].map(hidden);
          screen.append(bar("Recent activity", "🔔 1"), body(...rows));
          for (const r of rows) await api.reveal(r, 550);
        },
      },
      {
        title: "Your assets",
        pose: "point",
        say: "The Assets page shows everything you protect, each with its own padlock. From here you can scan again, open the report, pause protection or remove an asset. Your assets are private: no other account can ever see them.",
        async build(screen, api) {
          const a = row("g", "myshop.ng", "Black box · scanned 1h ago", "Protected", "g");
          const b = row("a", "myshop-api", "White box · scanned 3h ago", "Needs attention", "a");
          const again = btn("Scan again", "ghost");
          screen.append(bar("Assets"), body(a, b, again, btn("Report", "ghost")));
          await api.wait(1200);
          await api.tap(b);
          await api.tap(again);
        },
      },
      {
        title: "You're ready",
        pose: "cheer",
        say: "That's everything: secure your account with your phone, choose a scan, give permission, prove ownership for websites, read the fixes, then press Protect. You can watch this video again any time from the top of your dashboard. Stay safe out there!",
        async build(screen, api) {
          const hero = el("div", { class: "ls-hero" }, lock("green closed"), el("h3", { text: "You're protected" }), el("p", { text: "Scan · Detect · Secure" }));
          screen.append(hero);
          await api.wait(1200);
          api.hideTap();
        },
      },
    ];
  }

  function open(opts) {
    if (!window.Guide) return null;
    return window.Guide.open({
      title: "How Lucent Shield works",
      scenes: scenes(),
      logo: "/guide-mark.png",
      logoBare: true,
      chestText: "Lucent Shield",
      chestSub: "Security Beyond Boundaries",
      hoodie: "#132a52",
      hoodieDark: "#0b1a36",
      lang: "en-GB",
      // F / M buttons: a female or male presenter, each with a matching voice.
      looks: {
        female: { hairStyle: "puffs", band: "#2fe6a6", skin: "#8a5233", skinDark: "#6f3f24" },
        male: { glasses: true, skin: "#7a4a2a", skinDark: "#5f3720" },
      },
      onClose: opts && opts.onClose,
    });
  }

  window.LucentTour = { open };
})();
