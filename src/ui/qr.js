/*
 * A small QR code encoder (byte mode, error correction level L, versions 1 to 10,
 * up to 271 bytes), enough for an authenticator setup link. No outside code.
 * Exposes globalThis.lucentQR.matrix(text) -> boolean[][] (true = dark).
 */
(() => {
  "use strict";
  // [total codewords, ec codewords per block, [[blocks, data codewords per block], ...]] for level L.
  const TABLE = [null,
    [26, 7, [[1, 19]]], [44, 10, [[1, 34]]], [70, 15, [[1, 55]]], [100, 20, [[1, 80]]], [134, 26, [[1, 108]]],
    [172, 18, [[2, 68]]], [196, 20, [[2, 78]]], [242, 24, [[2, 97]]], [292, 30, [[2, 116]]], [346, 18, [[2, 68], [2, 69]]]];
  const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

  // Galois field GF(256) with the QR polynomial 0x11D.
  const EXP = new Array(512);
  const LOG = new Array(256);
  for (let i = 0, x = 1; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 256) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

  function ecCodewords(data, n) {
    let gen = [1];
    for (let i = 0; i < n; i++) {
      const next = new Array(gen.length + 1).fill(0);
      for (let j = 0; j < gen.length; j++) {
        next[j] ^= gen[j];
        next[j + 1] ^= mul(gen[j], EXP[i]);
      }
      gen = next;
    }
    const rem = new Array(n).fill(0);
    for (const d of data) {
      const f = d ^ rem.shift();
      rem.push(0);
      for (let j = 0; j < n; j++) rem[j] ^= mul(gen[j + 1], f);
    }
    return rem;
  }

  function utf8(text) {
    return Array.from(new TextEncoder().encode(text));
  }

  function codewords(bytes) {
    let version = 1;
    for (; version <= 10; version++) {
      const [total, ec, groups] = TABLE[version];
      const dataCap = groups.reduce((n, [b, d]) => n + b * d, 0);
      const bits = 4 + (version < 10 ? 8 : 16) + bytes.length * 8;
      if (bits <= dataCap * 8) break;
      void total;
      void ec;
    }
    if (version > 10) throw new Error("Too long for a QR code here.");
    const [, ecLen, groups] = TABLE[version];
    const dataCap = groups.reduce((n, [b, d]) => n + b * d, 0);
    const bits = [];
    const put = (v, n) => {
      for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1);
    };
    put(4, 4);
    put(bytes.length, version < 10 ? 8 : 16);
    for (const b of bytes) put(b, 8);
    put(0, Math.min(4, dataCap * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
    for (let pad = 0xec; data.length < dataCap; pad ^= 0xec ^ 0x11) data.push(pad);
    // Split into blocks, add error correction, interleave.
    const blocks = [];
    let at = 0;
    for (const [count, size] of groups) for (let i = 0; i < count; i++) {
      const d = data.slice(at, at + size);
      at += size;
      blocks.push({ d, e: ecCodewords(d, ecLen) });
    }
    const out = [];
    const maxD = Math.max(...blocks.map((b) => b.d.length));
    for (let i = 0; i < maxD; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i]);
    for (let i = 0; i < ecLen; i++) for (const b of blocks) out.push(b.e[i]);
    return { version, out };
  }

  function bch(value, poly, polyBits) {
    let v = value << (polyBits - 1);
    for (let i = 31 - Math.clz32(v); i >= polyBits - 1; i--) if ((v >>> i) & 1) v ^= poly << (i - (polyBits - 1));
    return v;
  }

  const MASKS = [
    (r, c) => (r + c) % 2 === 0, (r) => r % 2 === 0, (r, c) => c % 3 === 0, (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0, (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0, (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ];

  function build(version, cw, mask) {
    const size = version * 4 + 17;
    const m = Array.from({ length: size }, () => new Array(size).fill(false));
    const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
    const set = (r, c, v) => {
      m[r][c] = v;
      fixed[r][c] = true;
    };
    const finder = (r0, c0) => {
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
        const rr = r0 + r;
        const cc = c0 + c;
        if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
        const inner = r >= 0 && r <= 6 && c >= 0 && c <= 6 && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
        set(rr, cc, inner);
      }
    };
    finder(0, 0);
    finder(0, size - 7);
    finder(size - 7, 0);
    for (let i = 8; i < size - 8; i++) {
      set(6, i, i % 2 === 0);
      set(i, 6, i % 2 === 0);
    }
    const al = ALIGN[version];
    for (const r of al) for (const c of al) {
      if ((r === 6 && c === 6) || (r === 6 && c === al[al.length - 1]) || (r === al[al.length - 1] && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
    // Format information (level L = 01).
    const fmt = (bch((1 << 3) | mask, 0x537, 11) | (((1 << 3) | mask) << 10)) ^ 0x5412;
    const fbit = (i) => ((fmt >>> i) & 1) === 1;
    // (row, column)
    for (let i = 0; i <= 5; i++) set(i, 8, fbit(i));
    set(7, 8, fbit(6));
    set(8, 8, fbit(7));
    set(8, 7, fbit(8));
    for (let i = 9; i < 15; i++) set(8, 14 - i, fbit(i));
    for (let i = 0; i < 8; i++) set(8, size - 1 - i, fbit(i));
    for (let i = 8; i < 15; i++) set(size - 15 + i, 8, fbit(i));
    set(size - 8, 8, true); // the dark module
    if (version >= 7) {
      const vi = bch(version, 0x1f25, 13) | (version << 12);
      for (let i = 0; i < 18; i++) {
        const b = ((vi >>> i) & 1) === 1;
        const a = Math.floor(i / 3);
        const bb = (i % 3) + size - 11;
        set(a, bb, b);
        set(bb, a, b);
      }
    }
    // Data, in the zigzag order, with the mask.
    let bit = 0;
    const total = cw.length * 8;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
        const c = right - j;
        const upward = ((right + 1) & 2) === 0;
        const r = upward ? size - 1 - vert : vert;
        if (fixed[r][c]) continue;
        let dark = false;
        if (bit < total) dark = ((cw[bit >>> 3] >>> (7 - (bit & 7))) & 1) === 1;
        bit++;
        m[r][c] = dark !== MASKS[mask](r, c);
      }
    }
    return m;
  }

  function penalty(m) {
    const n = m.length;
    let p = 0;
    for (let pass = 0; pass < 2; pass++) for (let i = 0; i < n; i++) {
      let run = 1;
      for (let j = 1; j < n; j++) {
        const a = pass ? m[j][i] : m[i][j];
        const b = pass ? m[j - 1][i] : m[i][j - 1];
        if (a === b) {
          run++;
          if (run === 5) p += 3;
          else if (run > 5) p++;
        } else run = 1;
      }
    }
    for (let r = 0; r < n - 1; r++) for (let c = 0; c < n - 1; c++) if (m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c] && m[r][c] === m[r + 1][c + 1]) p += 3;
    const pat = [true, false, true, true, true, false, true, false, false, false, false];
    const rev = [...pat].reverse();
    for (let r = 0; r < n; r++) for (let c = 0; c + 11 <= n; c++) for (const q of [pat, rev]) {
      if (q.every((v, k) => m[r][c + k] === v)) p += 40;
      if (q.every((v, k) => m[c + k][r] === v)) p += 40;
    }
    let dark = 0;
    for (const row of m) for (const v of row) if (v) dark++;
    p += Math.floor(Math.abs((dark * 100) / (n * n) - 50) / 5) * 10;
    return p;
  }

  function matrix(text) {
    const { version, out } = codewords(utf8(text));
    let best = null;
    let bestScore = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const m = build(version, out, mask);
      const s = penalty(m);
      if (s < bestScore) {
        best = m;
        bestScore = s;
      }
    }
    return best;
  }

  globalThis.lucentQR = { matrix };
})();
