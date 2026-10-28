// Simple, dependency-free persistence in the data directory (a Bash Cloud
// disk, or ./data locally): user accounts, the assets each user protects and
// their last scan, alerts, and the audit trails. JSON files written atomically.

import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { countBySeverity, type Finding, type ScanResult } from "../types.ts";
import { shieldFor, type AssetKind, type Shield } from "../engine.ts";

export interface User {
  id: string;
  email: string;
  name: string;
  /** scrypt hash of the password, with its own random salt. Never the password. */
  salt: string;
  hash: string;
  createdAt: string;
  lastLoginAt: string | null;
  /** Scans this account has run (shown on its dashboard). */
  scans: number;
  /** Two-step login: the authenticator secret, the last code step used (no code
   *  works twice), and hashes of the unused recovery codes. */
  totp?: { secret: string; lastStep: number; recovery: string[]; enabledAt: string };
  /** A secret being set up, not active until a code from it is confirmed. */
  totpPending?: { secret: string; at: string };
}

/** What is safe to send to a browser about a user. */
export type PublicUser = Omit<User, "salt" | "hash" | "totp" | "totpPending"> & { twoStep: boolean; recoveryLeft: number };
export const publicUser = ({ salt, hash, totp, totpPending, ...u }: User): PublicUser => ({ ...u, twoStep: !!totp, recoveryLeft: totp?.recovery.length ?? 0 });

export interface Asset {
  id: string;
  /** The account this asset belongs to. Only that account can see or scan it. */
  ownerId?: string;
  name: string;
  kind: AssetKind;
  target: string;
  /** The operator confirmed they own or are authorised to test this. */
  authorized: boolean;
  /** Web assets must prove domain ownership before they can be scanned. */
  verified: boolean;
  /** The token the operator publishes (DNS or file) to prove domain ownership. */
  verifyToken: string;
  /** Protected: re-scan automatically on the monitor schedule. Turned on only
   *  by the owner pressing Protect, which records a standing authorization. */
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
  ownerId?: string;
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
const USERS_FILE = join(DATA_DIR, "users.json");
const EVENTS_FILE = join(DATA_DIR, "events.json");

export type EventType = "added" | "verified" | "scan" | "autoscan" | "protect-on" | "protect-off" | "removed";
export interface ActivityEvent { id: string; ownerId: string; assetId: string; assetName: string; type: EventType; text: string; at: string; shield?: string }

const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
function hashPassword(password: string, salt: string): string {
  return scryptSync(password, Buffer.from(salt, "hex"), 64, SCRYPT).toString("hex");
}
// Used when an email has no account, so a wrong email takes as long as a wrong password.
const DUMMY_SALT = randomBytes(16).toString("hex");

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

function loadUsers(): User[] {
  return readJson<User[]>(USERS_FILE, []);
}
function persistUsers(users: User[]): void {
  writeJson(USERS_FILE, users);
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

  /* ---------- accounts ---------- */

  userByEmail(email: string): User | undefined {
    const e = email.trim().toLowerCase();
    return loadUsers().find((u) => u.email === e);
  },
  user(id: string): User | undefined {
    return loadUsers().find((u) => u.id === id);
  },
  listUsers(): User[] {
    return loadUsers().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },
  createUser(input: { email: string; name: string; password: string }): User {
    const users = loadUsers();
    const email = input.email.trim().toLowerCase();
    if (users.some((u) => u.email === email)) throw new Error("exists");
    const salt = randomBytes(16).toString("hex");
    const user: User = { id: randomUUID(), email, name: input.name.trim().slice(0, 80), salt, hash: hashPassword(input.password, salt), createdAt: new Date().toISOString(), lastLoginAt: null, scans: 0 };
    users.push(user);
    persistUsers(users);
    return user;
  },
  /** The account for this email and password, or undefined. Same work either way. */
  checkPassword(email: string, password: string): User | undefined {
    const u = this.userByEmail(email);
    const got = Buffer.from(hashPassword(password, u?.salt ?? DUMMY_SALT), "hex");
    const want = Buffer.from(u?.hash ?? "00".repeat(64), "hex");
    return u && got.length === want.length && timingSafeEqual(got, want) ? u : undefined;
  },
  /** Applies a change to one account and saves it. */
  updateUser(id: string, change: (u: User) => void): User | undefined {
    const users = loadUsers();
    const u = users.find((x) => x.id === id);
    if (!u) return undefined;
    change(u);
    persistUsers(users);
    return u;
  },
  setTotpPending(id: string, secret: string): void {
    this.updateUser(id, (u) => { u.totpPending = { secret, at: new Date().toISOString() }; });
  },
  /** The pending secret, if it was started within the last 15 minutes. */
  totpPending(id: string): string | undefined {
    const p = this.user(id)?.totpPending;
    return p && Date.now() - Date.parse(p.at) < 15 * 60_000 ? p.secret : undefined;
  },
  enableTotp(id: string, secret: string, recovery: string[], step: number): void {
    this.updateUser(id, (u) => { u.totp = { secret, lastStep: step, recovery, enabledAt: new Date().toISOString() }; delete u.totpPending; });
  },
  disableTotp(id: string): void {
    this.updateUser(id, (u) => { delete u.totp; delete u.totpPending; });
  },
  /** Records a code step as used; false if it (or a later one) was already used. */
  useTotpStep(id: string, step: number): boolean {
    let ok = false;
    this.updateUser(id, (u) => { if (u.totp && step > u.totp.lastStep) { u.totp.lastStep = step; ok = true; } });
    return ok;
  },
  /** Spends a recovery code; each one works once. */
  useRecoveryCode(id: string, hash: string): boolean {
    let ok = false;
    this.updateUser(id, (u) => {
      const i = u.totp?.recovery.indexOf(hash) ?? -1;
      if (u.totp && i >= 0) { u.totp.recovery.splice(i, 1); ok = true; }
    });
    return ok;
  },

  touchLogin(id: string): void {
    const users = loadUsers();
    const u = users.find((x) => x.id === id);
    if (u) { u.lastLoginAt = new Date().toISOString(); persistUsers(users); }
  },
  /** Assets and alerts from before accounts existed go to the admin. */
  claimUnowned(ownerId: string): void {
    const assets = load();
    if (assets.some((a) => !a.ownerId)) persist(assets.map((a) => (a.ownerId ? a : { ...a, ownerId })));
    const alerts = loadAlerts();
    if (alerts.some((a) => !a.ownerId)) persistAlerts(alerts.map((a) => (a.ownerId ? a : { ...a, ownerId })));
  },

  /* ---------- assets ---------- */

  /** Every asset (monitor and admin), or only one account's. */
  list(ownerId?: string): Asset[] {
    return load().filter((a) => ownerId === undefined || a.ownerId === ownerId).sort((a, b) => (b.lastScanAt ?? b.createdAt).localeCompare(a.lastScanAt ?? a.createdAt));
  },

  get(id: string): Asset | undefined {
    return load().find((a) => a.id === id);
  },

  add(input: { ownerId: string; name: string; kind: AssetKind; target: string; authorized: boolean }): Asset {
    const assets = load();
    const web = input.kind === "web";
    const asset: Asset = {
      id: randomUUID(),
      ownerId: input.ownerId,
      name: input.name,
      kind: input.kind,
      target: input.target,
      authorized: input.authorized,
      // Only websites need domain-ownership proof; a local path or uploaded
      // artifact is already on the operator's own machine.
      verified: !web,
      verifyToken: web ? randomUUID().replace(/-/g, "") : "",
      monitor: false,
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
    if (asset.ownerId) {
      const users = loadUsers();
      const u = users.find((x) => x.id === asset.ownerId);
      if (u) { u.scans = (u.scans ?? 0) + 1; persistUsers(users); }
    }
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

  listAlerts(ownerId?: string): Alert[] {
    return loadAlerts().filter((a) => ownerId === undefined || a.ownerId === ownerId);
  },

  unreadAlerts(ownerId: string): number {
    return this.listAlerts(ownerId).filter((a) => !a.read).length;
  },

  markAlertsRead(ownerId: string): void {
    persistAlerts(loadAlerts().map((a) => (a.ownerId === ownerId ? { ...a, read: true } : a)));
  },

  /** Audit record: the operator gave explicit authorization to test a target. */
  logAuthorization(entry: { assetId: string; name: string; kind: string; target: string; ip: string; userId?: string; email?: string; reference?: string }): void {
    const list = readJson<any[]>(AUTH_FILE, []);
    list.unshift({ ...entry, at: new Date().toISOString() });
    writeJson(AUTH_FILE, list.slice(0, 1000));
  },

  /** What happened to an account's assets, for its Recent activity. Only real events. */
  addEvent(e: Omit<ActivityEvent, "id" | "at">): void {
    const list = readJson<ActivityEvent[]>(EVENTS_FILE, []);
    list.unshift({ ...e, id: randomUUID(), at: new Date().toISOString() });
    writeJson(EVENTS_FILE, list.slice(0, 3000));
  },
  events(ownerId: string, limit = 50): ActivityEvent[] {
    return readJson<ActivityEvent[]>(EVENTS_FILE, []).filter((e) => e.ownerId === ownerId).slice(0, limit);
  },

  /**
   * Websites that were scanned before their owner proved control of the domain
   * (possible in older versions through monitoring) lose those results and stop
   * being watched until they are verified and scanned with authorization.
   */
  resetUnverifiedScans(): number {
    const assets = load();
    let n = 0;
    for (const a of assets) {
      if (a.kind === "web" && !a.verified && (a.lastScanAt || a.monitor)) {
        a.lastScanAt = null; a.findings = []; a.counts = countBySeverity([]); a.shield = "new"; a.monitor = false; n++;
      }
    }
    if (n) persist(assets);
    return n;
  },

  /** The authorization audit trail, newest first. */
  listAuthorizations(limit = 1000): any[] {
    return readJson<any[]>(AUTH_FILE, []).slice(0, limit);
  },

  /** Sign-in history for the admin view. Never stores passwords. */
  logLogin(entry: { ip: string; email: string; event: "login" | "signup" | "code" | "recovery" | "2fa-on" | "2fa-off"; ok: boolean }): void {
    const list = readJson<any[]>(LOGINS_FILE, []);
    list.unshift({ ...entry, at: new Date().toISOString() });
    writeJson(LOGINS_FILE, list.slice(0, 500));
  },
  listLogins(limit = 500): any[] {
    return readJson<any[]>(LOGINS_FILE, []).slice(0, limit);
  },
};
