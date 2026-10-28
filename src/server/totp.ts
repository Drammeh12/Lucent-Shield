/**
 * Two-step login codes (TOTP, RFC 6238): the 6-digit codes that Google
 * Authenticator, Microsoft Authenticator, Authy and others show every 30 seconds.
 * Built on Node's own crypto; no outside packages.
 */
import { createHmac, randomBytes, timingSafeEqual, createHash } from "node:crypto";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error("Not a valid setup key.");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** A new secret: 20 random bytes, written in base32 for the authenticator app. */
export const newTotpSecret = () => base32Encode(randomBytes(20));

const STEP = 30;
export const stepAt = (ms = Date.now()) => Math.floor(ms / 1000 / STEP);

export function codeFor(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", Buffer.from(base32Decode(secret))).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  const n = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

/**
 * Checks a code, allowing one step either side for phone clocks that drift.
 * Returns the step it matched (so it can never be used twice), or null.
 */
export function verifyCode(secret: string, code: string, lastUsedStep: number, ms = Date.now()): number | null {
  const clean = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) return null;
  const now = stepAt(ms);
  for (const step of [now - 1, now, now + 1]) {
    if (step <= lastUsedStep) continue;
    const expected = Buffer.from(codeFor(secret, step));
    if (timingSafeEqual(expected, Buffer.from(clean))) return step;
  }
  return null;
}

/** What the authenticator app needs (it can also be typed in by hand). */
export function otpauthUri(secret: string, account: string, issuer = "Lucent Shield"): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${STEP}`;
}

/** Ten one-time recovery codes for a lost phone, like "7KQ4-M9XT". Only hashes are stored. */
export function newRecoveryCodes(): { codes: string[]; hashes: string[] } {
  const codes = Array.from({ length: 10 }, () => {
    const raw = base32Encode(randomBytes(5)).slice(0, 8);
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
  });
  return { codes, hashes: codes.map(hashRecovery) };
}

export const hashRecovery = (code: string) => createHash("sha256").update(code.toUpperCase().replace(/[\s-]/g, "")).digest("hex");
