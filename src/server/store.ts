// Simple, dependency-free persistence: the assets you protect and their last
// scan, saved as one JSON file in the data directory (a Bash Cloud disk, or
// ./data locally). Single-user, so no database is needed.

import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from "node:fs";
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
  /** Web assets must prove domain ownership before they can be scanned. */
  verified: boolean;
  /** The token the operator publishes (DNS or file) to prove domain ownership. */
  verifyToken: string;
  /** Re-scan this asset automatically on the monitor schedule. */
  monitor: boolean;
  createdAt: string;
  lastScanAt: string | null;
  shield: Shield;
  counts: ReturnType<typeof countBySeverity>;
  findings: Finding[];
  /** How many files the last scan read (repo and forensic scans). */
  filesScanned?: number;
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
const AUTH_FILE = join(DATA_DIR, "authorizations.json");
const LOGINS_FILE = join(DATA_DIR, "logins.json");

/** Writes JSON atomically: a crash mid-write can never leave a half-written file. */
function writeJson(path: string, data: unknown, pretty = true): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${path}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, pretty ? 2 : 0));
  renameSync(tmp, path);
}

/** Reads JSON. A damaged file is set aside (never silently overwritten) and the fallback is used. */
function readJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch (err) {
    const saved = `${path}.corrupt-${Date.now()}`;
    try { renameSync(path, saved); } catch { /* ignore */ }
    console.error(`Lucent Shield: ${path} could not be read; it was kept as ${saved}.`, err instanceof Error ? err.message : err);
    return fallback;
  }
}

function loadMeta(): { scans: number } {
  return readJson(META_FILE, { scans: 0 });
}
function persistMeta(meta: { scans: number }): void {
  writeJson(META_FILE, meta, false);
}

function load(): Asset[] {
  return readJson<Asset[]>(FILE, []);
}

function persist(assets: Asset[]): void {
  writeJson(FILE, assets);
}

function loadAlerts(): Alert[] {
  return readJson<Alert[]>(ALERTS_FILE, []);
}

function persistAlerts(alerts: Alert[]): void {
  writeJson(ALERTS_FILE, alerts.slice(0, 200)); // keep the most recent 200
}

// One scan per asset at a time (a button press and the monitor can't collide).
const scanning = new Set<string>();

export const store = {
  /** Claims the asset for scanning; false if it is already being scanned. */
  beginScan(id: string): boolean {
    if (scanning.has(id)) return false;
    scanning.add(id);
    return true;
  },
  endScan(id: string): void {
    scanning.delete(id);
  },

  list(): Asset[] {
    return load().sort((a, b) => (b.lastScanAt ?? b.createdAt).localeCompare(a.lastScanAt ?? a.createdAt));
  },

  get(id: string): Asset | undefined {
    return load().find((a) => a.id === id);
  },

  add(input: { name: string; kind: AssetKind; target: string; authorized: boolean }): Asset {
    const assets = load();
    const web = input.kind === "web";
    const asset: Asset = {
      id: randomUUID(),
      name: input.name,
      kind: input.kind,
      target: input.target,
      authorized: input.authorized,
      // Only websites need domain-ownership proof; a local path or uploaded
      // artifact is already on the operator's own machine.
      verified: !web,
      verifyToken: web ? randomUUID().replace(/-/g, "") : "",
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

  setVerified(id: string, verified: boolean): Asset | undefined {
    const assets = load();
    const asset = assets.find((a) => a.id === id);
    if (!asset) return undefined;
    asset.verified = verified;
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
    asset.filesScanned = result.filesScanned;
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

  /** Audit record: the operator gave explicit authorization to test a target. */
  logAuthorization(entry: { assetId: string; name: string; kind: string; target: string; ip: string; reference?: string }): void {
    const list = readJson<any[]>(AUTH_FILE, []);
    list.unshift({ ...entry, at: new Date().toISOString() });
    writeJson(AUTH_FILE, list.slice(0, 1000));
  },

  /** The authorization audit trail, newest first. */
  listAuthorizations(limit = 1000): any[] {
    return readJson<any[]>(AUTH_FILE, []).slice(0, limit);
  },

  /** Sign-in history for the admin view. Never stores passwords. */
  logLogin(entry: { ip: string; role: "admin" | "user"; ok: boolean }): void {
    const list = readJson<any[]>(LOGINS_FILE, []);
    list.unshift({ ...entry, at: new Date().toISOString() });
    writeJson(LOGINS_FILE, list.slice(0, 500));
  },
  listLogins(limit = 500): any[] {
    return readJson<any[]>(LOGINS_FILE, []).slice(0, limit);
  },
};
