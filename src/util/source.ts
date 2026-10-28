// Small helpers for reading source code more like a reviewer would.

/** Test, spec, fixture and mock files: code that is never deployed. */
const TEST_PATH =
  /(?:^|\/)(?:test|tests|__tests__|spec|specs|fixtures?|__fixtures__|mocks?|__mocks__|e2e|cypress|testdata)\/|\.(?:test|spec|e2e)\.[cm]?[jt]sx?$|_test\.(?:go|py|rb)$|(?:^|\/)test_[^/]+\.py$|Tests?\.(?:java|cs|kt)$|_spec\.rb$/i;

export function isTestPath(rel: string): boolean {
  return TEST_PATH.test(rel);
}

/** Obviously fabricated values used in docs and tests: ABCDEFG..., 1234567..., aaaaaaaa. */
const FAKE = /ABCDEFG|abcdefg|0123456|1234567|(.)\1{7}/;
export function looksFake(value: string): boolean {
  return FAKE.test(value);
}

/**
 * True when position `idx` in a line of C-like code (JS, TS, Java, Go, C#, PHP)
 * falls inside a string, template or regex literal, i.e. it is text, not code.
 * A light lexer: good enough to tell `eval(x)` from the words "eval()" in a label.
 */
export function insideLiteral(line: string, idx: number): boolean {
  let state: null | '"' | "'" | "`" | "/" = null;
  let inClass = false;
  let prev = ""; // last non-space character outside literals
  for (let i = 0; i < idx && i < line.length; i++) {
    const c = line[i];
    if (state) {
      if (c === "\\") { i++; continue; }
      if (state === "/") {
        if (c === "[") inClass = true;
        else if (c === "]") inClass = false;
        else if (c === "/" && !inClass) state = null;
        continue;
      }
      if (c === state) state = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { state = c; continue; }
    if (c === "/" && line[i + 1] !== "/" && line[i + 1] !== "*" && (prev === "" || "(,=:[!&|?{};+-*%<>~^".includes(prev))) {
      state = "/"; inClass = false; continue;
    }
    if (c === "/" && line[i + 1] === "/") return true; // the rest of the line is a comment, so it is text
    if (c.trim()) prev = c;
  }
  return state !== null;
}

/**
 * Inline suppression for findings a person has reviewed and accepted:
 * add "lucent-ignore" to the line (with a reason), or "lucent-ignore-next-line"
 * on the line above it.
 */
export function isSuppressed(lines: string[], i: number): boolean {
  return /lucent-ignore\b(?!-next-line)/.test(lines[i] ?? "") || /lucent-ignore-next-line\b/.test(lines[i - 1] ?? "");
}
