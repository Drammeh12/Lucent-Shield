// Walks a project directory, returning the text files worth scanning.
// Skips dependency folders, build output, version control, and binaries,
// so a scan is fast and never trips over huge or non-text files.

import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, extname } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", "dist", "build", ".next", "out",
  "vendor", "__pycache__", ".venv", "venv", "env", "coverage", ".cache",
  ".turbo", ".parcel-cache", "target", "bin", "obj", ".idea", ".vscode",
]);

// Extensions we never read as text.
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".svg",
  ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".xz",
  ".mp4", ".webm", ".mov", ".avi", ".mp3", ".wav", ".ogg", ".flac",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".wasm",
  ".pyc", ".o", ".a", ".node",
]);

export interface ScanFile {
  path: string;
  /** Path relative to the scan root, for clean reporting. */
  rel: string;
  lines: string[];
  text: string;
}

// Lockfiles are large but hold the exact versions we need, so they get more room.
const BIG_OK = /^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|cargo\.lock|gemfile\.lock|poetry\.lock|pipfile\.lock|packages\.lock\.json)$/i;

/** Safety limits so a huge repository can never exhaust the server. */
export const WALK_LIMITS = { maxFiles: 30_000, maxTotalBytes: 400_000_000, maxDepth: 40 };

export interface WalkResult { files: ScanFile[]; truncated: boolean; skippedLarge: number }

/** Returns the files under `root` that should be scanned as source text. */
export function walk(root: string, maxBytes = 2_000_000): ScanFile[] {
  return walkWithStats(root, maxBytes).files;
}

/** Like walk, but also reports whether limits cut the scan short. */
export function walkWithStats(root: string, maxBytes = 2_000_000): WalkResult {
  const out: ScanFile[] = [];
  const rootPrefix = root.endsWith("/") ? root : root + "/";
  let total = 0, truncated = false, skippedLarge = 0;

  const recurse = (dir: string, depth: number) => {
    if (depth > WALK_LIMITS.maxDepth) { truncated = true; return; }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= WALK_LIMITS.maxFiles || total >= WALK_LIMITS.maxTotalBytes) { truncated = true; return; }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        recurse(full, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = extname(entry.name).toLowerCase();
      if (BINARY_EXT.has(ext)) continue;
      if (entry.name.endsWith(".min.js") || entry.name.endsWith(".map")) continue;

      let stat;
      try {
        stat = statSync(full);
      } catch {
        continue;
      }
      const limit = BIG_OK.test(entry.name) ? 40_000_000 : maxBytes;
      if (stat.size === 0) continue;
      if (stat.size > limit) { skippedLarge++; continue; }
      total += stat.size;

      let text: string;
      try {
        text = readFileSync(full, "utf8");
      } catch {
        continue;
      }
      // Skip anything that looks binary (a NUL byte in the first chunk).
      if (text.slice(0, 4096).includes("\u0000")) continue;

      out.push({
        path: full,
        rel: full.startsWith(rootPrefix) ? full.slice(rootPrefix.length) : full,
        lines: text.split(/\r?\n/),
        text,
      });
    }
  };

  recurse(root, 0);
  return { files: out, truncated, skippedLarge };
}
