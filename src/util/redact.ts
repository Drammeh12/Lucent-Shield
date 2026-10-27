// Keeps secrets out of the report. A finding should prove something was
// there without ever printing the usable value.

/** Shows only the first few and last few characters: "AKIA………7F2Q". */
export function redact(value: string, keepStart = 4, keepEnd = 3): string {
  const v = value.trim();
  if (v.length <= keepStart + keepEnd) return "•".repeat(v.length);
  return `${v.slice(0, keepStart)}${"•".repeat(6)}${v.slice(-keepEnd)}`;
}

/** Trims a source line and redacts any long token-like runs inside it. */
export function redactLine(line: string, maxLen = 120): string {
  let out = line.trim();
  // Redact long base64/hex-ish runs that are likely the secret itself.
  out = out.replace(/[A-Za-z0-9_\-+/=]{20,}/g, (m) => redact(m));
  if (out.length > maxLen) out = out.slice(0, maxLen) + "…";
  return out;
}

/** Shannon entropy in bits per character — high for random secrets. */
export function entropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}
