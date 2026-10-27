// Simple, dependency-free persistence: the assets you protect and their last
// scan, saved as one JSON file in the data directory (a Bash Cloud disk, or
// ./data locally). Single-user, so no database is needed.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { countBySeverity, type Finding, type ScanResult } from "../types.ts";
import { shieldFor, type AssetKind, type Shield } from "../engine.ts";

export interface Asset {
  id: string;
  name: string;
  kind: AssetKind;
  target: string;
  /** The operator confirmed they own or are authorised to test this. */
  authorized: boolean;
  createdAt: string;
  lastScanAt: string | null;
  shield: Shield;
  counts: ReturnType<typeof countBySeverity>;
  findings: Finding[];
}

const DATA_DIR = resolve(process.env.LUCENT_DATA_DIR ?? "data");
const FILE = join(DATA_DIR, "assets.json");

function load(): Asset[] {
  try {
    return JSON.parse(readFileSync(FILE, "utf8")) as Asset[];
  } catch {
    return [];
  }
}

function persist(assets: Asset[]): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(FILE, JSON.stringify(assets, null, 2));
}

export const store = {
  list(): Asset[] {
    return load().sort((a, b) => (b.lastScanAt ?? b.createdAt).localeCompare(a.lastScanAt ?? a.createdAt));
  },

  get(id: string): Asset | undefined {
    return load().find((a) => a.id === id);
  },

  add(input: { name: string; kind: AssetKind; target: string; authorized: boolean }): Asset {
    const assets = load();
    const asset: Asset = {
      id: randomUUID(),
      name: input.name,
      kind: input.kind,
      target: input.target,
      authorized: input.authorized,
      createdAt: new Date().toISOString(),
      lastScanAt: null,
      shield: "new",
      counts: countBySeverity([]),
      findings: [],
    };
    assets.push(asset);
    persist(assets);
    return asset;
  },

  remove(id: string): boolean {
    const assets = load();
    const next = assets.filter((a) => a.id !== id);
    if (next.length === assets.length) return false;
    persist(next);
    return true;
  },

  saveScan(id: string, result: ScanResult): Asset | undefined {
    const assets = load();
    const asset = assets.find((a) => a.id === id);
    if (!asset) return undefined;
    asset.lastScanAt = result.finishedAt;
    asset.findings = result.findings;
    asset.counts = countBySeverity(result.findings);
    asset.shield = shieldFor(result.findings);
    persist(assets);
    return asset;
  },
};
