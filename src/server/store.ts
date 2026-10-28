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
  /** Re-scan this asset automatically on the monitor schedule. */
  monitor: boolean;
  createdAt: string;
  lastScanAt: string | null;
  shield: Shield;
  counts: ReturnType<typeof countBySeverity>;
  findings: Finding[];
}

export type AlertType = "worsened" | "recovered" | "new-issues";

export interface Alert {
  id: string;
  assetId: string;
  assetName: string;
  type: AlertType;
  message: string;
  at: string;
  read: boolean;
}

const DATA_DIR = resolve(process.env.LUCENT_DATA_DIR ?? "data");
const FILE = join(DATA_DIR, "assets.json");
const ALERTS_FILE = join(DATA_DIR, "alerts.json");
const META_FILE = join(DATA_DIR, "meta.json");

function loadMeta(): { scans: number } {
  try { return JSON.parse(readFileSync(META_FILE, "utf8")); } catch { return { scans: 0 }; }
}
function persistMeta(meta: { scans: number }): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(META_FILE, JSON.stringify(meta));
}

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

function loadAlerts(): Alert[] {
  try {
    return JSON.parse(readFileSync(ALERTS_FILE, "utf8")) as Alert[];
  } catch {
    return [];
  }
}

function persistAlerts(alerts: Alert[]): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  // Keep the most recent 200.
  writeFileSync(ALERTS_FILE, JSON.stringify(alerts.slice(0, 200), null, 2));
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
      monitor: true,
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
    const meta = loadMeta();
    meta.scans++;
    persistMeta(meta);
    return asset;
  },

  scanCount(): number {
    return loadMeta().scans;
  },

  setMonitor(id: string, on: boolean): Asset | undefined {
    const assets = load();
    const asset = assets.find((a) => a.id === id);
    if (!asset) return undefined;
    asset.monitor = on;
    persist(assets);
    return asset;
  },

  addAlert(input: Omit<Alert, "id" | "at" | "read">): Alert {
    const alerts = loadAlerts();
    const alert: Alert = { id: randomUUID(), at: new Date().toISOString(), read: false, ...input };
    alerts.unshift(alert);
    persistAlerts(alerts);
    return alert;
  },

  listAlerts(): Alert[] {
    return loadAlerts();
  },

  unreadAlerts(): number {
    return loadAlerts().filter((a) => !a.read).length;
  },

  markAlertsRead(): void {
    persistAlerts(loadAlerts().map((a) => ({ ...a, read: true })));
  },
};
