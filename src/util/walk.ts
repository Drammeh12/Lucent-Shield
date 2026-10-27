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

/** Returns the files under `root` that should be scanned as source text. */
export function walk(root: string, maxBytes = 2_000_000): ScanFile[] {
  const out: ScanFile[] = [];
  const rootPrefix = root.endsWith("/") ? root : root + "/";

  const recurse = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        recurse(full);
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
      if (stat.size > maxBytes || stat.size === 0) continue;

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

  recurse(root);
  return out;
}
