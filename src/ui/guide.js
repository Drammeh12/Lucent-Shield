/*
 * The guide: a friendly cartoon presenter in a branded hoodie who explains the product,
 * scene by scene, while a phone beside them shows each step being done.
 *
 * - Narration uses the browser's own voice (nothing to download); captions are always shown.
 * - Everything is drawn here (SVG and HTML), no video files, so it loads instantly.
 * - Works with a strict Content-Security-Policy: no inline style attributes, only el.style.
 *
 * Usage: Guide.open({ scenes, hoodie, logo, labels, ... }). Each scene is
 *   { title, say, pose: "wave" | "point" | "think" | "cheer", build(screen, api) }
 * where build() fills the phone screen and uses api.wait / api.tap / api.type to act it out.
 */
(function () {
  "use strict";

  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function el(tag, props, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) node.append(kid instanceof Node ? kid : String(kid));
    return node;
  }

  /** The presenter: an original character, drawn in SVG, wearing the product's hoodie. */
  function character(o) {
    const hoodie = o.hoodie || "#2f86ff";
    const dark = o.hoodieDark || "#0a5cf5";
    const skin = o.skin || "#9a5b34";
    const skinDark = o.skinDark || "#7d4626";
    const hair = o.hair || "#1d1820";
    // The print on the chest: a logo on a white patch, or printed straight on (with an optional name under it).
    const esc = (t) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
    const logo = !o.logo ? "" : o.logoBare
      ? `<image href="${o.logo}" x="98" y="${o.chestText ? 212 : 218}" width="44" height="40"/>` +
        (o.chestText ? `<text x="120" y="266" text-anchor="middle" font-family="system-ui, sans-serif" font-weight="800" font-size="10.5" fill="#ffffff">${esc(o.chestText)}</text>` : "") +
        (o.chestSub ? `<text x="120" y="276" text-anchor="middle" font-family="system-ui, sans-serif" font-weight="600" font-size="5" fill="#e6fff1" opacity=".9">${esc(o.chestSub)}</text>` : "")
      : `<circle cx="120" cy="238" r="23" fill="#ffffff"/><image href="${o.logo}" x="102" y="220" width="36" height="36"/>`;
    // Short curly hair, or two puffs with a headband in the product's colour.
    const hairSvg = o.hairStyle === "puffs"
      ? `<circle cx="74" cy="46" r="24" fill="${hair}"/><circle cx="166" cy="46" r="24" fill="${hair}"/>
         <path d="M71 98 Q64 46 120 42 Q176 46 169 98 Q160 66 120 62 Q80 66 71 98 Z" fill="${hair}"/>
         <path d="M78 70 Q120 48 162 70" stroke="${o.band || hoodie}" stroke-width="7" fill="none" stroke-linecap="round"/>
         <circle cx="64" cy="118" r="4.5" fill="#ffd36b"/><circle cx="176" cy="118" r="4.5" fill="#ffd36b"/>`
      : `<path d="M71 96 Q66 44 120 40 Q174 44 169 96 Q163 70 144 64 Q122 74 98 64 Q78 70 71 96 Z" fill="${hair}"/>
      <g fill="${hair}"><circle cx="82" cy="60" r="11"/><circle cx="98" cy="48" r="12"/><circle cx="118" cy="43" r="12"/><circle cx="138" cy="47" r="12"/><circle cx="156" cy="58" r="11"/><circle cx="166" cy="74" r="8"/><circle cx="74" cy="76" r="8"/></g>`;
    const wrap = el("div", { class: "g-char", "aria-hidden": "true" });
    wrap.innerHTML = `
<svg viewBox="0 0 240 330" xmlns="http://www.w3.org/2000/svg">
  <ellipse class="g-shadow" cx="120" cy="322" rx="78" ry="7" fill="#000" opacity=".25"/>
  <g class="g-body">
    <path d="M66 156 Q120 108 174 156 L178 182 L62 182 Z" fill="${dark}"/>
    <path d="M52 196 Q58 162 96 156 L144 156 Q182 162 188 196 L194 318 Q120 326 46 318 Z" fill="${hoodie}"/>
    <path d="M70 300 L170 300 L172 316 Q120 322 68 316 Z" fill="${dark}" opacity=".55"/>
    <rect x="108" y="138" width="24" height="26" rx="9" fill="${skinDark}"/>
    <path d="M86 158 Q120 192 154 158 Q142 178 120 180 Q98 178 86 158 Z" fill="${dark}"/>
    <path d="M109 176 L107 206" stroke="#f4f6ff" stroke-width="3" stroke-linecap="round"/>
    <path d="M131 176 L133 206" stroke="#f4f6ff" stroke-width="3" stroke-linecap="round"/>
    <circle cx="107" cy="209" r="3.6" fill="#f4f6ff"/><circle cx="133" cy="209" r="3.6" fill="#f4f6ff"/>
    ${logo}
    <path d="M86 284 Q120 276 154 284 L158 306 L82 306 Z" fill="${dark}" opacity=".45"/>
    <g class="g-arm g-arm-r">
      <path d="M62 190 Q40 236 50 286" stroke="${hoodie}" stroke-width="27" stroke-linecap="round" fill="none"/>
      <path d="M50 278 L50 290" stroke="${dark}" stroke-width="27" stroke-linecap="round"/>
      <circle cx="50" cy="298" r="13" fill="${skin}"/>
    </g>
    <g class="g-arm g-arm-l">
      <path d="M178 190 Q200 236 190 286" stroke="${hoodie}" stroke-width="27" stroke-linecap="round" fill="none"/>
      <path d="M190 278 L190 290" stroke="${dark}" stroke-width="27" stroke-linecap="round"/>
      <circle cx="190" cy="298" r="13" fill="${skin}"/>
      <path class="g-finger" d="M190 300 L190 316" stroke="${skin}" stroke-width="7" stroke-linecap="round"/>
    </g>
    <g class="g-head">
      <ellipse cx="72" cy="104" rx="10" ry="14" fill="${skinDark}"/>
      <ellipse cx="168" cy="104" rx="10" ry="14" fill="${skinDark}"/>
      <ellipse cx="120" cy="100" rx="49" ry="55" fill="${skin}"/>
      ${hairSvg}
      <path class="g-brow" d="M93 86 Q102 81 111 86" stroke="${hair}" stroke-width="4" fill="none" stroke-linecap="round"/>
      <path class="g-brow" d="M129 86 Q138 81 147 86" stroke="${hair}" stroke-width="4" fill="none" stroke-linecap="round"/>
      <g class="g-eyes">
        <ellipse cx="102" cy="102" rx="6.5" ry="7.5" fill="#1b1720"/><circle cx="104" cy="99.5" r="2" fill="#fff"/>
        <ellipse cx="138" cy="102" rx="6.5" ry="7.5" fill="#1b1720"/><circle cx="140" cy="99.5" r="2" fill="#fff"/>
      </g>
      ${o.glasses ? `<g fill="none" stroke="#1b1720" stroke-width="3"><circle cx="102" cy="102" r="12"/><circle cx="138" cy="102" r="12"/><path d="M114 101 Q120 97 126 101"/><path d="M90 100 L76 96"/><path d="M150 100 L164 96"/></g>` : ""}
      <circle cx="92" cy="120" r="7" fill="#e36a6a" opacity=".22"/><circle cx="148" cy="120" r="7" fill="#e36a6a" opacity=".22"/>
      <path d="M117 108 Q120 118 124 113" stroke="${skinDark}" stroke-width="3" fill="none" stroke-linecap="round"/>
      <path class="g-mouth-closed" d="M106 127 Q120 140 134 127" stroke="#3b1d1d" stroke-width="4" fill="none" stroke-linecap="round"/>
      <g class="g-mouth-open"><path d="M107 126 Q120 146 133 126 Z" fill="#5a1b25"/><path d="M111 127 L129 127 L127 131 L113 131 Z" fill="#fff"/></g>
    </g>
  </g>
</svg>`;
    return wrap;
  }

  // ---------------------------------------------------------------- narration

  // Voice names that are known to be female or male, across Chrome, Edge,
  // Safari, Android and Windows. Nigerian voices (Ezinne, Abeo) come first.
  const FEMALE = /ezinne|female|woman|zira|aria|jenny|sonia|libby|natasha|clara|emma|ava|samantha|karen|moira|tessa|serena|fiona|victoria|susan|hazel|heera|catherine|allison|joanna|amy|salli|kimberly|google us english|denise|elsa|julie|amelie|aurelie|celine/i;
  const MALE = /abeo|\bmale\b|\bman\b|guy|ryan|davis|tony|brian|christopher|eric|roger|steffan|william|daniel|alex|fred|thomas|arthur|oliver|david|mark|george|james|rishi|aaron|tom|henri|paul|claude|remy|gerard/i;

  /** The clearest voice for the language and the chosen presenter (female or male). */
  function pickVoice(lang, gender) {
    const synth = window.speechSynthesis;
    if (!synth) return null;
    const voices = synth.getVoices();
    const want = lang.toLowerCase();
    const short = want.split("-")[0];
    const score = (v) => {
      const l = (v.lang || "").toLowerCase().replace("_", "-");
      const name = v.name || "";
      let s = 0;
      if (l === want) s += 6;
      else if (l.startsWith(short)) s += 4;
      else return -1;
      if (/natural|neural|online|google|premium|enhanced/i.test(name)) s += 3;
      if (/en-ng|en-gh|en-ke|en-za/.test(l)) s += 2;
      const female = FEMALE.test(name);
      const male = !female && MALE.test(name);
      if (gender === "female") s += female ? 8 : male ? -8 : 0;
      if (gender === "male") s += male ? 8 : female ? -8 : 0;
      return s;
    };
    const best = voices.filter((v) => score(v) >= 0).sort((a, b) => score(b) - score(a))[0] || null;
    const known = best && (FEMALE.test(best.name) ? "female" : MALE.test(best.name) ? "male" : null);
    return best ? { voice: best, matches: known === gender } : null;
  }

  function open(cfg) {
    const scenes = cfg.scenes;
    const L = Object.assign({ play: "Play", pause: "Pause", next: "Next", back: "Back", close: "Close", soundOn: "Sound on", soundOff: "Sound off", again: "Watch again", of: "of" }, cfg.labels || {});
    const lang = cfg.lang || "en-GB";
    let index = 0;
    let playing = true;
    let ended = false;
    let sound = !!window.speechSynthesis;
    try {
      if (localStorage.getItem("guide-sound") === "off") sound = false;
    } catch {}
    let token = 0;
    const previouslyFocused = document.activeElement;

    // Female or male presenter (and voice): the M / F buttons switch it.
    const looks = cfg.looks || null;
    let gender = cfg.gender || "female";
    try {
      const saved = localStorage.getItem("guide-voice");
      if (looks && (saved === "female" || saved === "male")) gender = saved;
    } catch {}
    const lookFor = (g) => Object.assign({}, cfg, looks ? looks[g] : {});
    let char = character(lookFor(gender));
    const genderBtns = looks
      ? ["female", "male"].map((g) =>
          el("button", {
            class: "g-gender",
            type: "button",
            "aria-label": g === "female" ? "Female voice" : "Male voice",
            title: g === "female" ? "Female voice" : "Male voice",
            text: g === "female" ? "F" : "M",
          })
        )
      : [];
    const bubble = el("div", { class: "g-bubble", "aria-live": "polite" });
    const sceneTitle = el("div", { class: "g-scene-title" });
    const screen = el("div", { class: "g-screen" });
    const tap = el("div", { class: "g-tap", "aria-hidden": "true" });
    const phone = el("div", { class: "g-phone" }, el("div", { class: "g-notch" }), screen);
    const bar = el("div", { class: "g-progress-bar" });
    const chapters = el("ol", { class: "g-chapters" });
    const playBtn = el("button", { class: "g-btn g-primary", type: "button" });
    const soundBtn = el("button", { class: "g-btn", type: "button" });
    const backBtn = el("button", { class: "g-btn", type: "button", text: `\u2039 ${L.back}` });
    const nextBtn = el("button", { class: "g-btn", type: "button", text: `${L.next} \u203a` });
    const closeBtn = el("button", { class: "g-close", type: "button", "aria-label": L.close, text: "\u00d7" });
    const counter = el("span", { class: "g-count" });

    const stage = el("div", { class: "g-stage" },
      el("div", { class: "g-presenter" }, char, el("div", { class: "g-talk" }, sceneTitle, bubble)),
      el("div", { class: "g-device" }, phone));
    const dialog = el("div", { class: "g-modal", role: "dialog", "aria-modal": "true", "aria-label": cfg.title || "Guide", "data-no-translate": "" },
      el("div", { class: "g-card" },
        el("div", { class: "g-top" }, el("div", { class: "g-title" }, cfg.titleNode || cfg.title || "Guide"), closeBtn),
        stage,
        el("div", { class: "g-progress" }, bar),
        el("div", { class: "g-controls" }, backBtn, playBtn, nextBtn, counter, el("span", { class: "g-spacer" }),
          looks ? el("span", { class: "g-genders", role: "group", "aria-label": "Voice" }, genderBtns) : null, soundBtn),
        chapters));
    if (reduceMotion) dialog.classList.add("g-still");

    scenes.forEach((s, i) => chapters.append(el("li", {}, el("button", { type: "button", text: s.title, onclick: () => go(i) }))));

    const stopVoice = () => {
      try {
        window.speechSynthesis && window.speechSynthesis.cancel();
      } catch {}
    };

    const talking = (on) => char.classList.toggle("talking", on);

    /** Says the text (or waits as long as reading it would take). Resolves when done. */
    function speak(text, run) {
      const words = text.split(/\s+/).length;
      const reading = Math.max(2600, words * 380);
      return new Promise((resolve) => {
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          if (run === token) talking(false);
          resolve();
        };
        talking(true);
        // Never rush: even when a voice finishes early (or there is none), leave time to read.
        const started = Date.now();
        const atLeast = reading * 0.8;
        const end = finish;
        const finishLate = () => setTimeout(end, Math.max(0, atLeast - (Date.now() - started)));
        if (!sound || !window.speechSynthesis) {
          setTimeout(finish, reading);
          return;
        }
        stopVoice();
        const u = new SpeechSynthesisUtterance(text);
        u.lang = lang;
        // A normal, light voice at a normal pace (not deep, not slow).
        const picked = pickVoice(lang, gender);
        if (picked) u.voice = picked.voice;
        u.rate = 1.06;
        // When the device has no voice of the chosen kind, shift the pitch a little instead.
        u.pitch = picked && picked.matches ? 1.02 : gender === "female" ? 1.25 : 0.95;
        u.onend = finishLate;
        u.onerror = finishLate;
        // Some browsers never report the end of a long sentence: never wait forever.
        setTimeout(finish, reading * 1.8 + 2500);
        window.speechSynthesis.speak(u);
      });
    }

    function makeApi(run) {
      const alive = () => run === token;
      const wait = (ms) => new Promise((resolve, reject) => setTimeout(() => (alive() ? resolve() : reject(new Error("stopped"))), reduceMotion ? Math.min(ms, 250) : ms));
      return {
        el,
        wait,
        /** Moves the finger to an element on the phone and taps it. */
        async tap(target) {
          if (!target || !alive()) return;
          const s = screen.getBoundingClientRect();
          const r = target.getBoundingClientRect();
          tap.classList.add("g-show");
          tap.style.transform = `translate(${r.left - s.left + screen.scrollLeft + r.width / 2 - 14}px, ${r.top - s.top + screen.scrollTop + r.height / 2 - 6}px)`;
          await wait(700);
          tap.classList.add("g-down");
          target.classList.add("g-pressed");
          await wait(260);
          tap.classList.remove("g-down");
          target.classList.remove("g-pressed");
          await wait(250);
        },
        /** Types text into an element, a letter at a time. */
        async type(target, text, perChar = 45) {
          target.textContent = "";
          target.classList.add("g-typing");
          for (const ch of text) {
            target.textContent += ch;
            await wait(perChar);
          }
          target.classList.remove("g-typing");
        },
        /** Shows an element that was added hidden (class g-hide). */
        async reveal(node, ms = 300) {
          node.classList.remove("g-hide");
          node.classList.add("g-in");
          await wait(ms);
        },
        scroll(y) {
          screen.scrollTop = y;
        },
        hideTap() {
          tap.classList.remove("g-show");
        },
      };
    }

    function paint() {
      const s = scenes[index];
      sceneTitle.textContent = s.title;
      bubble.textContent = s.say;
      counter.textContent = `${index + 1} ${L.of} ${scenes.length}`;
      bar.style.width = `${((index + 1) / scenes.length) * 100}%`;
      [...chapters.children].forEach((li, i) => li.classList.toggle("g-current", i === index));
      backBtn.disabled = index === 0;
      nextBtn.disabled = index === scenes.length - 1;
      playBtn.textContent = playing ? `\u275a\u275a ${L.pause}` : ended ? `\u21bb ${L.again}` : `\u25b6 ${L.play}`;
      soundBtn.textContent = sound ? `\ud83d\udd0a ${L.soundOn}` : `\ud83d\udd07 ${L.soundOff}`;
      genderBtns.forEach((b, i) => {
        const g = i === 0 ? "female" : "male";
        b.classList.toggle("g-on", g === gender);
        b.setAttribute("aria-pressed", String(g === gender));
      });
      soundBtn.setAttribute("aria-pressed", String(sound));
      char.className = `g-char pose-${s.pose || "point"}`;
    }

    async function run() {
      const my = ++token;
      stopVoice();
      const s = scenes[index];
      paint();
      screen.replaceChildren(tap);
      tap.classList.remove("g-show", "g-down");
      screen.scrollTop = 0;
      const api = makeApi(my);
      try {
        await Promise.all([speak(s.voice || s.say, my), Promise.resolve(s.build(screen, api))]);
        if (my !== token) return;
        await api.wait(900);
      } catch {
        return; // a newer scene took over
      }
      if (my !== token || !playing) return;
      if (index < scenes.length - 1) {
        index++;
        run();
      } else {
        playing = false;
        ended = true;
        paint();
        if (cfg.onEnd) cfg.onEnd();
      }
    }

    function go(i) {
      index = Math.max(0, Math.min(scenes.length - 1, i));
      playing = true;
      ended = false;
      run();
    }

    function close() {
      token++;
      stopVoice();
      document.removeEventListener("keydown", onKey);
      dialog.remove();
      document.body.classList.remove("g-lock");
      if (previouslyFocused && previouslyFocused.focus) previouslyFocused.focus();
      if (cfg.onClose) cfg.onClose();
    }

    function onKey(e) {
      if (e.key === "Escape") close();
      else if (e.key === "ArrowRight" && index < scenes.length - 1) go(index + 1);
      else if (e.key === "ArrowLeft" && index > 0) go(index - 1);
      else if (e.key === " " && e.target === document.body) {
        e.preventDefault();
        playBtn.click();
      }
    }

    playBtn.addEventListener("click", () => {
      if (playing) {
        playing = false;
        token++;
        stopVoice();
        talking(false);
        paint();
      } else {
        go(ended ? 0 : index);
      }
    });
    genderBtns.forEach((b, i) =>
      b.addEventListener("click", () => {
        const g = i === 0 ? "female" : "male";
        if (g === gender) return;
        gender = g;
        try {
          localStorage.setItem("guide-voice", g);
        } catch {}
        const fresh = character(lookFor(g));
        char.replaceWith(fresh);
        char = fresh;
        paint();
        if (playing) run();
      })
    );
    soundBtn.addEventListener("click", () => {
      sound = !sound;
      try {
        localStorage.setItem("guide-sound", sound ? "on" : "off");
      } catch {}
      if (!sound) stopVoice();
      paint();
      if (playing) run();
    });
    backBtn.addEventListener("click", () => go(index - 1));
    nextBtn.addEventListener("click", () => go(index + 1));
    closeBtn.addEventListener("click", close);
    dialog.addEventListener("click", (e) => {
      if (e.target === dialog) close();
    });
    document.addEventListener("keydown", onKey);

    document.body.append(dialog);
    document.body.classList.add("g-lock");
    closeBtn.focus();
    // Voices load a moment after the page; start once they are known (or after a short wait).
    if (window.speechSynthesis && !window.speechSynthesis.getVoices().length) {
      let started = false;
      const start = () => {
        if (!started) {
          started = true;
          run();
        }
      };
      window.speechSynthesis.addEventListener("voiceschanged", start, { once: true });
      setTimeout(start, 600);
    } else run();
    return { close, go };
  }

  window.Guide = { open, el, character };
})();
